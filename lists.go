package netacl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// The lists in this repository's lists/ directory, refreshed weekly by the
// update-lists workflow.
const defaultListsURL = "https://raw.githubusercontent.com/tbshfr/caddy-netacl/main/lists"

// The largest published list, GitHub Actions, is about 120 kB; the cap only
// guards against a broken or malicious response.
const maxListSize = 16 << 20

var errNotModified = errors.New("not modified")

// remoteList is a list selector's data. The list's file is the cached copy in
// Caddy's data directory.
type remoteList struct {
	name string
	url  string
	list *ipList

	// Only used by the update loop once the app has started.
	etag    string
	sum     [sha256.Size]byte
	checked time.Time
}

// List names are paths below the base URL, so they are restricted to
// characters that need no escaping and segments that cannot climb out of it
// or out of the cache directory.
func validateListName(name string) error {
	invalid := fmt.Errorf("invalid list name %q: use lowercase letters, digits, '_', '-' and '.', with '/' between parts, e.g. github/hooks", name)
	if name == "" {
		return errors.New("empty list name")
	}
	for seg := range strings.SplitSeq(name, "/") {
		if seg == "" || seg[0] == '.' {
			return invalid
		}
		for _, r := range seg {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
				return invalid
			}
		}
	}
	return nil
}

// Lists feed allow rules, so plain HTTP would let anyone on the network path
// add addresses to them.
func validateListsURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("lists_url %q: must be an https URL", s)
	}
	return nil
}

// listsCacheDir returns the cache directory for one base URL. Each base URL
// gets its own, so changing lists_url never serves a list cached from the
// previous source.
func listsCacheDir(dataDir, baseURL string) string {
	sum := sha256.Sum256([]byte(baseURL))
	return filepath.Join(dataDir, "netacl", "lists", fmt.Sprintf("%x", sum[:8]))
}

// parseRemoteList is stricter than ip_file: the content comes from someone
// else, and an empty list or one matching everything is almost certainly a
// mistake upstream. In an allow rule, a /0 would open the site to everyone.
func parseRemoteList(name string, data []byte) (*ipListData, error) {
	d, err := parseIPList(bytes.NewReader(data), name, func(p netip.Prefix) error {
		if p.Bits() == 0 {
			return fmt.Errorf("%s matches every address", p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if d.count == 0 {
		return nil, fmt.Errorf("%s: no entries", name)
	}
	return d, nil
}

type listDownload struct {
	body []byte
	data *ipListData
	sum  [sha256.Size]byte
	etag string
}

// fetchList downloads and validates the list at url. With the etag of an
// earlier download, an unchanged list returns errNotModified.
func fetchList(ctx context.Context, client *http.Client, url, etag string) (*listDownload, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "caddy-netacl")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.Request.URL.Scheme != "https" {
		return nil, fmt.Errorf("%s: redirected to non-https URL %s", url, resp.Request.URL.Redacted())
	}
	switch {
	case resp.StatusCode == http.StatusNotModified && etag != "":
		return nil, errNotModified
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	if len(body) > maxListSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, maxListSize)
	}
	d, err := parseRemoteList(url, body)
	if err != nil {
		return nil, err
	}
	return &listDownload{body: body, data: d, sum: sha256.Sum256(body), etag: resp.Header.Get("ETag")}, nil
}

// writeFileAtomic replaces dst by rename, so readers never see a partial
// file.
func writeFileAtomic(dst string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), dst)
	}
	return err
}

func (a *App) remoteList(name string) (*ipList, error) {
	a.mu.Lock()
	l, ok := a.lists[name]
	a.mu.Unlock()
	if ok {
		return l.list, nil
	}

	// The lock is not held during the download.
	l, err := a.openList(name)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if cur, ok := a.lists[name]; ok {
		return cur.list, nil
	}
	a.lists[name] = l
	return l.list, nil
}

// openList loads the cached copy of a list, or downloads the list if there is
// no usable copy.
func (a *App) openList(name string) (*remoteList, error) {
	path := filepath.Join(a.listsDir, filepath.FromSlash(name)+".txt")
	l := &remoteList{name: name, url: a.ListsURL + "/" + name + ".txt", list: &ipList{path: path}}

	data, err := os.ReadFile(path)
	var st os.FileInfo
	if err == nil {
		st, err = os.Stat(path)
	}
	var d *ipListData
	if err == nil {
		d, err = parseRemoteList(path, data)
	}
	if err == nil {
		l.list.cur.Store(d)
		l.sum = sha256.Sum256(data)
		// The mtime is the last check, so restarts and config reloads do not
		// download the list again before it is due.
		l.checked = st.ModTime()
		a.logger.Info("loaded list", zap.String("list", name), zap.String("path", path), zap.Int("entries", d.count))
		return l, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		a.logger.Warn("cached list is unusable; downloading a fresh copy",
			zap.String("list", name), zap.String("path", path), zap.Error(err))
	}

	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	dl, err := fetchList(ctx, a.httpClient, l.url, "")
	cancel()
	if err == nil {
		err = writeFileAtomic(path, dl.body)
	}
	if err != nil {
		a.metrics.downloads.WithLabelValues("list", "error").Inc()
		return nil, fmt.Errorf("list %s: downloading: %w", name, err)
	}
	l.list.cur.Store(dl.data)
	l.sum, l.etag, l.checked = dl.sum, dl.etag, a.now()
	a.metrics.downloads.WithLabelValues("list", "success").Inc()
	a.logger.Info("downloaded list", zap.String("list", name), zap.String("url", l.url), zap.Int("entries", dl.data.count))
	return l, nil
}

func (a *App) listLoop(ctx context.Context) {
	for {
		a.updateLists(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(a.listCheckEvery):
		}
	}
}

// updateLists checks each list that has not been checked for listRefresh. A
// failed check is retried on the next run, every listCheckEvery.
func (a *App) updateLists(ctx context.Context) {
	a.mu.Lock()
	lists := make([]*remoteList, 0, len(a.lists))
	for _, l := range a.lists {
		lists = append(lists, l)
	}
	a.mu.Unlock()

	for _, l := range lists {
		now := a.now()
		if now.Sub(l.checked) < a.listRefresh {
			continue
		}
		dl, err := fetchList(ctx, a.httpClient, l.url, l.etag)
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, errNotModified):
		case err != nil:
			a.metrics.downloads.WithLabelValues("list", "error").Inc()
			a.logger.Error("list update failed; keeping the loaded list", zap.String("list", l.name), zap.Error(err))
			continue
		case dl.sum == l.sum:
			l.etag = dl.etag
		default:
			if err := writeFileAtomic(l.list.path, dl.body); err != nil {
				a.metrics.downloads.WithLabelValues("list", "error").Inc()
				a.logger.Error("list update failed; keeping the loaded list", zap.String("list", l.name), zap.Error(err))
				continue
			}
			l.list.cur.Store(dl.data)
			l.sum, l.etag = dl.sum, dl.etag
			a.metrics.downloads.WithLabelValues("list", "success").Inc()
			a.logger.Info("updated list", zap.String("list", l.name), zap.String("url", l.url), zap.Int("entries", dl.data.count))
		}
		l.checked = now
		if err := os.Chtimes(l.list.path, now, now); err != nil {
			a.logger.Debug("cannot record list check time", zap.String("list", l.name), zap.Error(err))
		}
	}
}
