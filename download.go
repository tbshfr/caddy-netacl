package netacl

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const dbipBaseURL = "https://download.db-ip.com/free"

// The databases are about 10 MB; the cap only guards against a broken or
// malicious response filling the disk or, since databases are read into
// memory, the RAM.
const maxDBSize = 256 << 20

var errNotPublished = errors.New("release not published yet")

func dbipFileName(kind dbKind) string {
	return "dbip-" + kind.String() + "-lite.mmdb"
}

func releaseMonth(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// fetchDBIP downloads the DB-IP Lite release of the given month and installs
// it at dst. The download is verified before the rename, so dst only ever
// holds a complete, valid database. The returned handle describes the
// installed file.
func fetchDBIP(ctx context.Context, client *http.Client, baseURL string, kind dbKind, month time.Time, dst string) (*dbHandle, error) {
	url := fmt.Sprintf("%s/dbip-%s-lite-%s.mmdb.gz", baseURL, kind, month.Format("2006-01"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "caddy-netacl")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: %w", url, errNotPublished)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	// Same directory as dst, so the rename is atomic.
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(zr, maxDBSize+1))
	if err == nil && n > maxDBSize {
		err = fmt.Errorf("larger than %d bytes", maxDBSize)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	h, err := loadDB(kind, tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return nil, err
	}
	// The rename keeps the inode, size and mtime, so h.stat still matches dst
	// and the reload_interval loop does not load the file a second time.
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return nil, err
	}
	return h, nil
}

// fetchLatestDBIP tries the current month first and falls back to the
// previous one, because each release appears a few hours into the month.
func fetchLatestDBIP(ctx context.Context, client *http.Client, baseURL string, kind dbKind, now time.Time, dst string) (*dbHandle, error) {
	cur := releaseMonth(now)
	h, err := fetchDBIP(ctx, client, baseURL, kind, cur, dst)
	if errors.Is(err, errNotPublished) {
		h, err = fetchDBIP(ctx, client, baseURL, kind, cur.AddDate(0, -1, 0), dst)
	}
	return h, err
}
