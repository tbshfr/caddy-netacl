package netacl

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

type fakeDBIP struct {
	srv *httptest.Server

	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
}

func newFakeDBIP(t *testing.T) *fakeDBIP {
	f := &fakeDBIP{files: map[string][]byte{}, hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		body, ok := f.files[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func fakePath(kind dbKind, month time.Time) string {
	return fmt.Sprintf("/dbip-%s-lite-%s.mmdb.gz", kind, month.Format("2006-01"))
}

func (f *fakeDBIP) publish(t *testing.T, kind dbKind, month time.Time, raw []byte) {
	t.Helper()
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	zw.Write(raw)
	zw.Close()
	f.mu.Lock()
	f.files[fakePath(kind, month)] = buf.Bytes()
	f.mu.Unlock()
}

func (f *fakeDBIP) publishReal(t *testing.T, kind dbKind, month time.Time) {
	t.Helper()
	raw, err := os.ReadFile(testDB(t, kind))
	if err != nil {
		t.Fatal(err)
	}
	f.publish(t, kind, month, raw)
}

func (f *fakeDBIP) hitCount(kind dbKind, month time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[fakePath(kind, month)]
}

// newAutoApp provisions an auto_update app whose data directory is a fresh
// temporary directory, unless dataHome is given.
func newAutoApp(t *testing.T, f *fakeDBIP, dataHome string, a *App) *App {
	t.Helper()
	if dataHome == "" {
		dataHome = t.TempDir()
	}
	t.Setenv("XDG_DATA_HOME", dataHome)
	a.AutoUpdate = true
	a.dbipURL = f.srv.URL
	a.httpClient = f.srv.Client()
	app, _ := newTestApp(t, a)
	return app
}

func managedPath(kind dbKind) string {
	return filepath.Join(os.Getenv("XDG_DATA_HOME"), "caddy", "netacl", dbipFileName(kind))
}

var countryPolicy = Policy{Rules: []Rule{{Action: "allow", Selector: Selector{Countries: []string{"DE"}}}}, Default: "deny"}

func TestAutoUpdateDownloadsOnFirstUse(t *testing.T) {
	month := releaseMonth(time.Now())
	f := newFakeDBIP(t)
	f.publishReal(t, dbCountry, month)
	f.publishReal(t, dbASN, month)

	dataHome := t.TempDir()
	app := newAutoApp(t, f, dataHome, &App{})
	e, err := countryPolicy.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if e.evaluate(newRequest(ipHetzner)).Action != ActionAllow {
		t.Error("downloaded database does not serve lookups")
	}
	st, err := os.Stat(managedPath(dbCountry))
	if err != nil {
		t.Fatalf("database not stored in the data directory: %v", err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v, want 0644", st.Mode().Perm())
	}
	// Only databases that a rule needs are downloaded.
	if _, err := os.Stat(managedPath(dbASN)); !os.IsNotExist(err) {
		t.Errorf("unused ASN database was downloaded: %v", err)
	}
	if got := testutil.ToFloat64(app.metrics.downloads.WithLabelValues("country", "success")); got != 1 {
		t.Errorf("downloads = %v, want 1", got)
	}

	// After a restart the stored file is used without downloading again.
	app2 := newAutoApp(t, f, dataHome, &App{})
	if _, err := countryPolicy.compile(app2, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if n := f.hitCount(dbCountry, month); n != 1 {
		t.Errorf("downloaded %d times, want 1", n)
	}
}

func TestAutoUpdateReplacesUnusableStoredFile(t *testing.T) {
	month := releaseMonth(time.Now())
	f := newFakeDBIP(t)
	f.publishReal(t, dbCountry, month)

	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	if err := os.MkdirAll(filepath.Dir(managedPath(dbCountry)), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, managedPath(dbCountry), "truncated")

	app := newAutoApp(t, f, dataHome, &App{})
	e, err := countryPolicy.compile(app, zap.NewNop())
	if err != nil {
		t.Fatalf("a corrupt managed file must be downloaded again: %v", err)
	}
	if e.evaluate(newRequest(ipHetzner)).Action != ActionAllow {
		t.Error("downloaded database does not serve lookups")
	}
	if n := f.hitCount(dbCountry, month); n != 1 {
		t.Errorf("downloaded %d times, want 1", n)
	}
}

func TestUnusableExplicitFileIsNotReplaced(t *testing.T) {
	f := newFakeDBIP(t)
	path := filepath.Join(t.TempDir(), "country.mmdb")
	writeFile(t, path, "truncated")
	app := newAutoApp(t, f, "", &App{DBCountry: path})
	if _, err := countryPolicy.compile(app, zap.NewNop()); err == nil {
		t.Fatal("want error for a corrupt explicitly configured file")
	}
	if data, _ := os.ReadFile(path); string(data) != "truncated" {
		t.Error("explicitly configured file was overwritten")
	}
}

func TestAutoUpdateFallsBackToPreviousMonth(t *testing.T) {
	now := time.Now()
	prev := releaseMonth(now).AddDate(0, -1, 0)
	f := newFakeDBIP(t)
	f.publishReal(t, dbCountry, prev)

	app := newAutoApp(t, f, "", &App{})
	if _, err := countryPolicy.compile(app, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if f.hitCount(dbCountry, releaseMonth(now)) != 1 || f.hitCount(dbCountry, prev) != 1 {
		t.Errorf("want one request for each month, got %v", f.hits)
	}
}

func TestAutoUpdateDownloadErrors(t *testing.T) {
	month := releaseMonth(time.Now())
	tests := []struct {
		name    string
		publish func(f *fakeDBIP)
		want    string
	}{
		{"not published", func(f *fakeDBIP) {}, "not published"},
		{"not gzip", func(f *fakeDBIP) {
			f.files[fakePath(dbCountry, month)] = []byte("<html>maintenance</html>")
		}, "gzip"},
		{"not an mmdb", func(f *fakeDBIP) { f.publish(t, dbCountry, month, []byte("garbage")) }, "db_country"},
		{"wrong type", func(f *fakeDBIP) {
			raw, err := os.ReadFile(testDB(t, dbASN))
			if err != nil {
				t.Fatal(err)
			}
			f.publish(t, dbCountry, month, raw)
		}, "not a country or city database"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDBIP(t)
			tc.publish(f)
			app := newAutoApp(t, f, "", &App{})
			_, err := countryPolicy.compile(app, zap.NewNop())
			if err == nil || !strings.Contains(err.Error(), "auto_update: downloading the country database") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want auto_update error containing %q", err, tc.want)
			}
			// Nothing, not even a temporary file, is left behind.
			entries, _ := os.ReadDir(filepath.Dir(managedPath(dbCountry)))
			if len(entries) != 0 {
				t.Errorf("left files behind: %v", entries)
			}
		})
	}
}

func TestAutoUpdateLeavesExplicitPathsAlone(t *testing.T) {
	month := releaseMonth(time.Now())
	f := newFakeDBIP(t)
	f.publishReal(t, dbASN, month)

	country := testDB(t, dbCountry)
	app := newAutoApp(t, f, "", &App{DBCountry: country})
	p := Policy{Rules: []Rule{
		{Action: "deny", Selector: Selector{ASNs: []uint32{15169}}},
		{Action: "allow", Selector: Selector{Countries: []string{"DE"}}},
	}, Default: "deny"}
	if _, err := p.compile(app, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if app.managed[dbCountry] || !app.managed[dbASN] {
		t.Errorf("managed = %v, want only asn", app.managed)
	}
	if app.country.path != country {
		t.Errorf("country path changed to %s", app.country.path)
	}
	if f.hitCount(dbCountry, month) != 0 {
		t.Error("explicitly configured country database was downloaded")
	}
}

func TestUpdateOnce(t *testing.T) {
	f := newFakeDBIP(t)
	f.publishReal(t, dbCountry, releaseMonth(time.Now()))
	app := newAutoApp(t, f, "", &App{})
	e, err := countryPolicy.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	loaded := func() *dbHandle { return app.country.cur.Load() }
	first := loaded()
	ctx := context.Background()
	fetched := map[dbKind]time.Time{}

	app.now = func() time.Time { return first.built }
	app.updateOnce(ctx, fetched)
	if loaded() != first || len(f.hits) != 1 {
		t.Fatalf("up-to-date database was checked or replaced: %v", f.hits)
	}

	next := releaseMonth(first.built).AddDate(0, 1, 0)
	app.now = func() time.Time { return next.Add(3 * time.Hour) }

	app.updateOnce(ctx, fetched)
	if loaded() != first || f.hitCount(dbCountry, next) != 1 {
		t.Fatal("unpublished release: want one request and no change")
	}
	if got := testutil.ToFloat64(app.metrics.downloads.WithLabelValues("country", "error")); got != 0 {
		t.Errorf("an unpublished release counted as error")
	}

	f.publish(t, dbCountry, next, []byte("garbage"))
	app.updateOnce(ctx, fetched)
	if loaded() != first {
		t.Fatal("bad download replaced the loaded database")
	}
	if _, err := loadDB(dbCountry, managedPath(dbCountry)); err != nil {
		t.Fatalf("bad download damaged the stored file: %v", err)
	}
	if got := testutil.ToFloat64(app.metrics.downloads.WithLabelValues("country", "error")); got != 1 {
		t.Errorf("download errors = %v, want 1", got)
	}

	f.publishReal(t, dbCountry, next)
	app.updateOnce(ctx, fetched)
	if loaded() == first {
		t.Fatal("new release was not installed")
	}
	if e.evaluate(newRequest(ipHetzner)).Action != ActionAllow {
		t.Error("new release does not serve lookups")
	}
	// The real file's build date is still in the previous month, so only
	// fetched stops it from being downloaded on every check.
	hits := f.hitCount(dbCountry, next)
	app.updateOnce(ctx, fetched)
	if f.hitCount(dbCountry, next) != hits {
		t.Error("the same release was downloaded twice")
	}
}

func TestUpdateLoop(t *testing.T) {
	f := newFakeDBIP(t)
	f.publishReal(t, dbCountry, releaseMonth(time.Now()))
	app := newAutoApp(t, f, "", &App{})
	if _, err := countryPolicy.compile(app, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	first := app.country.cur.Load()
	next := releaseMonth(first.built).AddDate(0, 1, 0)
	f.publishReal(t, dbCountry, next)
	app.now = func() time.Time { return next }
	app.updateEvery = 10 * time.Millisecond

	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for app.country.cur.Load() == first {
		if time.Now().After(deadline) {
			t.Fatal("update loop did not install the new release")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stopped := make(chan struct{})
	go func() { app.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return")
	}
}
