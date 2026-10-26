package netacl

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

// The lists published from this repository must pass the checks every
// download goes through. The update-lists workflow runs this before it
// commits.
func TestPublishedLists(t *testing.T) {
	n := 0
	err := filepath.WalkDir("lists", func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || filepath.Ext(path) != ".txt" {
			return err
		}
		n++
		name := strings.TrimSuffix(filepath.ToSlash(strings.TrimPrefix(path, "lists"+string(filepath.Separator))), ".txt")
		if err := validateListName(name); err != nil {
			t.Error(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if _, err := parseRemoteList(path, data); err != nil {
			t.Error(err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no lists found in lists/")
	}
}

func TestValidateListName(t *testing.T) {
	for _, name := range []string{"github/hooks", "github/actions", "a", "x/y/z-1_2.v4"} {
		if err := validateListName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, name := range []string{"", "/github", "github/", "github//hooks", "../etc", "github/../x", ".hidden", "GitHub/hooks", "github/hooks?x", "a\\b"} {
		if err := validateListName(name); err == nil {
			t.Errorf("%q: want error", name)
		}
	}
}

func TestParseRemoteList(t *testing.T) {
	if _, err := parseRemoteList("l", []byte("192.0.2.0/24\n2001:db8::/32 # doc\n")); err != nil {
		t.Errorf("valid list: %v", err)
	}
	for body, want := range map[string]string{
		"":                            "l: no entries",
		"# only a comment\n\n":        "l: no entries",
		"192.0.2.0/24\n0.0.0.0/0\n":   "l:2: 0.0.0.0/0 matches every address",
		"::/0\n":                      "l:1: ::/0 matches every address",
		"192.0.2.0/24\nnot-an-ip\n":   `l:2: invalid IP or CIDR "not-an-ip"`,
		"::ffff:0.0.0.0/96\n":         "l:1: 0.0.0.0/0 matches every address",
		"192.0.2.0/24\n10.0.0.0/33\n": `l:2: invalid IP or CIDR "10.0.0.0/33"`,
	} {
		_, err := parseRemoteList("l", []byte(body))
		if err == nil || err.Error() != want {
			t.Errorf("%q: got %v, want %q", body, err, want)
		}
	}
}

type fakeLists struct {
	srv *httptest.Server

	mu          sync.Mutex
	files       map[string]string
	hits        map[string]int
	notModified int
}

func newFakeLists(t *testing.T) *fakeLists {
	f := &fakeLists{files: map[string]string{}, hits: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits[r.URL.Path]++
		body, ok := f.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256([]byte(body)))
		if r.Header.Get("If-None-Match") == etag {
			f.notModified++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLists) publish(path, body string) {
	f.mu.Lock()
	f.files[path] = body
	f.mu.Unlock()
}

func (f *fakeLists) unpublish(path string) {
	f.mu.Lock()
	delete(f.files, path)
	f.mu.Unlock()
}

func (f *fakeLists) notModifiedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.notModified
}

func (f *fakeLists) hitCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func newListApp(t *testing.T, f *fakeLists, dataHome string) *App {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", dataHome)
	app, _ := newTestApp(t, &App{
		ListsURL:   f.srv.URL + "/lists/",
		httpClient: f.srv.Client(),
		Groups:     map[string]Selector{"unused": {Lists: []string{"github/actions"}}},
	})
	return app
}

var hooksPolicy = Policy{Rules: []Rule{{Action: "allow", Selector: Selector{Lists: []string{"github/hooks"}}}}, Default: "deny"}

func TestListDownloadsOnFirstUse(t *testing.T) {
	f := newFakeLists(t)
	f.publish("/lists/github/hooks.txt", "# hooks\n192.0.2.0/24\n")
	f.publish("/lists/github/actions.txt", "198.51.100.0/24\n")

	dataHome := t.TempDir()
	app := newListApp(t, f, dataHome)
	e, err := hooksPolicy.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if e.evaluate(newRequest("192.0.2.7")).Action != ActionAllow || e.evaluate(newRequest("198.51.100.7")).Action != ActionDeny {
		t.Error("downloaded list does not decide")
	}
	cached := filepath.Join(app.listsDir, "github", "hooks.txt")
	if !strings.HasPrefix(cached, filepath.Join(dataHome, "caddy", "netacl", "lists")) {
		t.Errorf("list cached at %s, want it under the data directory", cached)
	}
	if st, err := os.Stat(cached); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("cached list: %v, %v", st, err)
	}
	// Lists only used by an unused group are not downloaded.
	if n := f.hitCount("/lists/github/actions.txt"); n != 0 {
		t.Errorf("unused list downloaded %d times", n)
	}
	if got := testutil.ToFloat64(app.metrics.downloads.WithLabelValues("list", "success")); got != 1 {
		t.Errorf("list downloads = %v, want 1", got)
	}

	// A restart uses the cache, and does not check before the list is due.
	app2 := newListApp(t, f, dataHome)
	e2, err := hooksPolicy.compile(app2, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	app2.updateLists(t.Context())
	if n := f.hitCount("/lists/github/hooks.txt"); n != 1 {
		t.Errorf("downloaded %d times, want 1", n)
	}
	if e2.evaluate(newRequest("192.0.2.7")).Action != ActionAllow {
		t.Error("cached list does not decide")
	}

	// A different lists_url does not reuse lists cached from another source.
	app3, _ := newTestApp(t, &App{ListsURL: f.srv.URL + "/other", httpClient: f.srv.Client()})
	if _, err := hooksPolicy.compile(app3, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("got %v, want a download error for the other lists_url", err)
	}
}

func TestListDownloadErrors(t *testing.T) {
	f := newFakeLists(t)
	f.publish("/lists/github/hooks.txt", "0.0.0.0/0\n")
	app := newListApp(t, f, t.TempDir())
	_, err := hooksPolicy.compile(app, zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "list github/hooks: downloading: ") || !strings.Contains(err.Error(), "matches every address") {
		t.Errorf("got %v", err)
	}
	p := Policy{Rules: []Rule{{Action: "deny", Selector: Selector{Lists: []string{"nope"}}}}, Default: "allow"}
	if _, err := p.compile(app, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "404 Not Found") {
		t.Errorf("missing list: got %v", err)
	}
	if got := testutil.ToFloat64(app.metrics.downloads.WithLabelValues("list", "error")); got != 2 {
		t.Errorf("list download errors = %v, want 2", got)
	}
	if _, err := os.Stat(filepath.Join(app.listsDir, "github", "hooks.txt")); !os.IsNotExist(err) {
		t.Errorf("rejected list was cached: %v", err)
	}
}

func TestListReplacesUnusableCache(t *testing.T) {
	f := newFakeLists(t)
	f.publish("/lists/github/hooks.txt", "192.0.2.0/24\n")
	dataHome := t.TempDir()
	app := newListApp(t, f, dataHome)
	cached := filepath.Join(app.listsDir, "github", "hooks.txt")
	if err := os.MkdirAll(filepath.Dir(cached), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cached, "")
	e, err := hooksPolicy.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if e.evaluate(newRequest("192.0.2.7")).Action != ActionAllow {
		t.Error("empty cached list was not replaced")
	}
}

func TestListUpdate(t *testing.T) {
	f := newFakeLists(t)
	const path = "/lists/github/hooks.txt"
	f.publish(path, "192.0.2.0/24\n")
	app := newListApp(t, f, t.TempDir())
	now := time.Now()
	app.now = func() time.Time { return now }
	e, err := hooksPolicy.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	decide := func(ip string) Action { return e.evaluate(newRequest(ip)).Action }
	cached := filepath.Join(app.listsDir, "github", "hooks.txt")

	f.publish(path, "198.51.100.0/24\n")
	app.updateLists(t.Context())
	if f.hitCount(path) != 1 || decide("192.0.2.7") != ActionAllow {
		t.Fatal("list checked before it was due")
	}

	now = now.Add(app.listRefresh)
	app.updateLists(t.Context())
	if decide("192.0.2.7") != ActionDeny || decide("198.51.100.7") != ActionAllow {
		t.Error("updated list not swapped in")
	}
	if data, _ := os.ReadFile(cached); string(data) != "198.51.100.0/24\n" {
		t.Errorf("cache holds %q", data)
	}
	if got := testutil.ToFloat64(app.metrics.downloads.WithLabelValues("list", "success")); got != 2 {
		t.Errorf("list downloads = %v, want 2", got)
	}

	// Unchanged: answered with 304 thanks to the ETag, and the check time is
	// recorded on the cached file.
	now = now.Add(app.listRefresh)
	app.updateLists(t.Context())
	if n := f.notModifiedCount(); n != 1 {
		t.Errorf("got %d conditional responses, want 1", n)
	}
	if st, err := os.Stat(cached); err != nil || !st.ModTime().Equal(now) {
		t.Errorf("cache mtime not set to the check time: %v, %v", st, err)
	}

	// Invalid and unreachable updates keep the loaded list and are retried on
	// the next run, without waiting for the next refresh.
	now = now.Add(app.listRefresh)
	f.publish(path, "nope\n")
	app.updateLists(t.Context())
	f.unpublish(path)
	app.updateLists(t.Context())
	if decide("198.51.100.7") != ActionAllow {
		t.Error("failed update replaced the loaded list")
	}
	if got := testutil.ToFloat64(app.metrics.downloads.WithLabelValues("list", "error")); got != 2 {
		t.Errorf("list download errors = %v, want 2", got)
	}
	f.publish(path, "203.0.113.0/24\n")
	app.updateLists(t.Context())
	if decide("203.0.113.7") != ActionAllow {
		t.Error("failed update was not retried")
	}
}

func TestListLoop(t *testing.T) {
	f := newFakeLists(t)
	f.publish("/lists/github/hooks.txt", "192.0.2.0/24\n")
	app := newListApp(t, f, t.TempDir())
	app.listRefresh = time.Millisecond
	app.listCheckEvery = time.Millisecond
	if _, err := hooksPolicy.compile(app, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.hitCount("/lists/github/hooks.txt") < 3 {
		if time.Now().After(deadline) {
			t.Fatal("update loop did not check the list")
		}
		time.Sleep(time.Millisecond)
	}
	app.Stop()
}

func TestListRedirectToHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("192.0.2.0/24\n"))
	}))
	t.Cleanup(plain.Close)
	redirect := httptest.NewTLSServer(http.RedirectHandler(plain.URL+"/hooks.txt", http.StatusFound))
	t.Cleanup(redirect.Close)

	_, err := fetchList(t.Context(), redirect.Client(), redirect.URL+"/hooks.txt", "")
	if err == nil || !strings.Contains(err.Error(), "redirected to non-https URL") {
		t.Errorf("got %v", err)
	}
}

func TestListsURLErrors(t *testing.T) {
	for _, u := range []string{"http://example.com/lists", "ftp://example.com/lists", "example.com/lists", "https://"} {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		err := (&App{ListsURL: u}).Provision(ctx)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "must be an https URL") {
			t.Errorf("%s: got %v", u, err)
		}
	}
}
