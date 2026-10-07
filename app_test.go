package netacl

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func newTestApp(t testing.TB, a *App) (*App, *observer.ObservedLogs) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := a.Provision(ctx); err != nil {
		t.Fatalf("provision app: %v", err)
	}
	core, logs := observer.New(zapcore.DebugLevel)
	a.logger = zap.New(core)
	t.Cleanup(func() { a.Stop() })
	return a, logs
}

func newRequest(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = net.JoinHostPort(ip, "40000")
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	return r.WithContext(ctx)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// replaceFile swaps dst by rename, as auto_update and well-behaved updaters do.
func replaceFile(t *testing.T, src, dst string) {
	t.Helper()
	tmp := dst + ".tmp"
	copyFile(t, src, tmp)
	if err := os.Rename(tmp, dst); err != nil {
		t.Fatal(err)
	}
}

func TestIPOnlyConfigNeverOpensDatabases(t *testing.T) {
	app, _ := newTestApp(t, &App{
		DBCountry: "/does/not/exist/country.mmdb",
		DBASN:     "/does/not/exist/asn.mmdb",
		Groups:    map[string]Selector{"office": {IPs: []string{"192.0.2.0/24"}}},
	})
	p := Policy{Rules: []Rule{{Action: "allow", Selector: Selector{Groups: []string{"office"}}}}, Default: "deny"}
	if _, err := p.compile(app, zap.NewNop()); err != nil {
		t.Fatalf("IP-only policy must not open databases: %v", err)
	}
	if app.country != nil || app.asn != nil {
		t.Error("a database was opened")
	}
}

func TestGeoGroupDefinedButUnusedDoesNotOpenDatabase(t *testing.T) {
	app, _ := newTestApp(t, &App{
		DBCountry: "/does/not/exist/country.mmdb",
		Groups:    map[string]Selector{"eu": {Continents: []string{"EU"}}},
	})
	p := Policy{Rules: []Rule{{Action: "allow", Selector: Selector{PrivateRanges: true}}}, Default: "deny"}
	if _, err := p.compile(app, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseErrors(t *testing.T) {
	country := testDB(t, dbCountry)
	tests := []struct {
		name string
		app  *App
		rule Selector
		want string
	}{
		{"country not configured", &App{}, Selector{Countries: []string{"DE"}},
			"a rule needs the country database, but db_country is not configured"},
		{"continent not configured", &App{}, Selector{Continents: []string{"EU"}},
			"db_country is not configured"},
		{"asn not configured", &App{DBCountry: country}, Selector{ASNs: []uint32{1}},
			"a rule needs the asn database, but db_asn is not configured"},
		{"missing file", &App{DBCountry: "/does/not/exist.mmdb"}, Selector{Countries: []string{"DE"}},
			"db_country: stat /does/not/exist.mmdb: no such file"},
		{"wrong type", &App{DBASN: country}, Selector{ASNs: []uint32{1}},
			`db_asn: ` + country + `: database type "DBIP-Country-Lite" is not an ASN database`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := newTestApp(t, tc.app)
			p := Policy{Rules: []Rule{{Action: "deny", Selector: tc.rule}}, Default: "allow"}
			_, err := p.compile(app, zap.NewNop())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestAppProvisionErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.txt")
	writeFile(t, bad, "192.0.2.1\n\n# comment\nbogus\n")
	tests := []struct {
		name string
		app  *App
		want string
	}{
		{"unreadable ip_file in group", &App{Groups: map[string]Selector{"g": {IPFiles: []string{filepath.Join(dir, "nope.txt")}}}},
			`group "g": ip_file: open`},
		{"invalid line in ip_file", &App{Groups: map[string]Selector{"g": {IPFiles: []string{bad}}}},
			`bad.txt:4: invalid IP or CIDR "bogus"`},
		{"cycle", &App{Groups: map[string]Selector{"a": {Groups: []string{"b"}}, "b": {Groups: []string{"a"}}}},
			"group cycle: a -> b -> a"},
		{"negative interval", &App{ReloadInterval: -1}, "reload_interval"},
		{"interval too short", &App{ReloadInterval: caddy.Duration(time.Millisecond)}, "reload_interval 1ms: must be 0 (off) or at least 1s"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			err := tc.app.Provision(ctx)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

// caddy.Validate provisions every module, like caddy validate and caddy run.
func TestValidateJSON(t *testing.T) {
	cfg := func(app, handler string) string {
		return `{"apps":{` + app + `"http":{"servers":{"s":{"listen":[":0"],"routes":[{"handle":[` + handler + `]}]}}}}}`
	}
	tests := []struct {
		name string
		json string
		want string // empty: must validate
	}{
		{"ok", cfg(`"netacl":{"db_country":"`+testDB(t, dbCountry)+`","groups":{"eu":{"continents":["EU"]}}},`,
			`{"handler":"netacl","rules":[{"action":"allow","groups":["eu"]}],"default":"deny"}`), ""},
		{"no app config, ip only", cfg(``,
			`{"handler":"netacl","rules":[{"action":"allow","private_ranges":true}],"default":"deny"}`), ""},
		{"no app config, group", cfg(``,
			`{"handler":"netacl","rules":[{"action":"allow","groups":["staff"]}],"default":"deny"}`),
			"unknown group @staff"},
		{"no app config, country", cfg(``,
			`{"handler":"netacl","rules":[{"action":"allow","countries":["DE"]}],"default":"deny"}`),
			"db_country is not configured"},
		{"missing default", cfg(``,
			`{"handler":"netacl","rules":[{"action":"allow","ips":["192.0.2.1"]}]}`),
			"missing default"},
		{"bad status", cfg(``,
			`{"handler":"netacl","default":"deny","status_code":302}`),
			"status_code 302"},
		{"matcher without decision", `{"apps":{"http":{"servers":{"s":{"listen":[":0"],"routes":[{"match":[{"netacl":{"default":"deny"}}],"handle":[{"handler":"static_response"}]}]}}}}}`,
			"missing decision"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c caddy.Config
			if err := json.Unmarshal([]byte(tc.json), &c); err != nil {
				t.Fatal(err)
			}
			err := caddy.Validate(&c)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("want valid, got %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestHandler(t *testing.T) {
	app, _ := newTestApp(t, &App{DBCountry: testDB(t, dbCountry), DBASN: testDB(t, dbASN)})
	h := &Handler{
		Policy: Policy{Rules: []Rule{
			{Action: "deny", Selector: Selector{ASNs: []uint32{15169}}},
			{Action: "allow", Selector: Selector{Countries: []string{"DE"}}},
		}, Default: "deny"},
		StatusCode: 451,
	}
	e, err := h.Policy.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	h.engine = e

	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	r := newRequest(ipHetzner)
	if err := h.ServeHTTP(httptest.NewRecorder(), r, next); err != nil || !nextCalled {
		t.Fatalf("allow: err=%v next=%v", err, nextCalled)
	}
	assertVars(t, r, map[string]string{
		VarDecision: "allow", VarRule: "1", VarCountry: "DE", VarContinent: "EU", VarASN: "24940",
	})

	nextCalled = false
	r = newRequest(ipGoogle)
	err = h.ServeHTTP(httptest.NewRecorder(), r, next)
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != 451 || nextCalled {
		t.Fatalf("deny: err=%v next=%v", err, nextCalled)
	}
	// The ASN rule decided, so the country was never looked up.
	assertVars(t, r, map[string]string{
		VarDecision: "deny", VarRule: "0", VarCountry: "", VarASN: "15169",
	})

	r = newRequest(ipUnknown)
	if err := h.ServeHTTP(httptest.NewRecorder(), r, next); err == nil {
		t.Fatal("want deny")
	}
	assertVars(t, r, map[string]string{
		VarDecision: "deny", VarRule: "default", VarCountry: "UNK", VarContinent: "", VarASN: "",
	})

	if got := testutil.ToFloat64(app.metrics.decisions.WithLabelValues("deny")); got != 2 {
		t.Errorf("deny decisions = %v, want 2", got)
	}
	if got := testutil.ToFloat64(app.metrics.lookups.WithLabelValues("country", "miss")); got != 1 {
		t.Errorf("country misses = %v, want 1", got)
	}
}

func TestHandlerLookupError(t *testing.T) {
	app, logs := newTestApp(t, &App{DBCountry: testDB(t, dbCountry)})
	h := &Handler{
		Policy: Policy{Rules: []Rule{
			{Action: "deny", Selector: Selector{Countries: []string{"US"}}},
		}, Default: "allow", OnLookupError: "deny"},
		StatusCode: 403,
	}
	e, err := h.Policy.compile(app, app.logger)
	if err != nil {
		t.Fatal(err)
	}
	geo := newFakeGeo()
	geo.err = errors.New("boom")
	e.src = geo
	h.engine = e

	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	for range 3 {
		r := newRequest(ipGoogle)
		err := h.ServeHTTP(httptest.NewRecorder(), r, next)
		if err == nil || !strings.Contains(err.Error(), "failed database lookup") {
			t.Fatalf("got %v, want deny by lookup error", err)
		}
		assertVars(t, r, map[string]string{VarDecision: "deny", VarRule: "lookup_error", VarCountry: ""})
	}
	if got := testutil.ToFloat64(app.metrics.lookups.WithLabelValues("country", "error")); got != 3 {
		t.Errorf("country errors = %v, want 3", got)
	}
	if n := logs.FilterMessageSnippet("database lookup failed").Len(); n != 1 {
		t.Errorf("logged %d lookup errors, want 1 per minute", n)
	}

	h.OnLookupError = "maybe"
	if _, err := h.Policy.compile(app, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "invalid on_lookup_error") {
		t.Errorf("got %v, want invalid on_lookup_error", err)
	}
}

func TestMatcherPolarity(t *testing.T) {
	app, _ := newTestApp(t, &App{})
	policy := Policy{Rules: []Rule{{Action: "deny", Selector: Selector{IPs: []string{"192.0.2.0/24"}}}}, Default: "allow"}
	for _, tc := range []struct {
		decision string
		ip       string
		want     bool
	}{
		{"deny", "192.0.2.1", true},
		{"deny", "198.51.100.1", false},
		{"allow", "192.0.2.1", false},
		{"allow", "198.51.100.1", true},
	} {
		m := &Matcher{Decision: tc.decision, Policy: policy}
		m.want, _ = ParseAction(tc.decision)
		e, err := m.Policy.compile(app, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		m.engine = e
		got, err := m.MatchWithError(newRequest(tc.ip))
		if err != nil || got != tc.want {
			t.Errorf("netacl %s, %s: got %v, %v; want %v", tc.decision, tc.ip, got, err, tc.want)
		}
	}
}

func TestClientIPVar(t *testing.T) {
	app, _ := newTestApp(t, &App{DBCountry: testDB(t, dbCountry)})
	p := Policy{Rules: []Rule{{Action: "allow", Selector: Selector{Countries: []string{"DE"}}}}, Default: "deny"}
	e, err := p.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	r := newRequest("10.0.0.1")
	caddyhttp.SetVar(r.Context(), caddyhttp.ClientIPVarKey, "::ffff:"+ipHetzner)
	if d := e.evaluate(r); d.Action != ActionAllow {
		t.Errorf("client_ip var ignored: %+v", d)
	}
	r = newRequest("10.0.0.1")
	r.Header.Set("X-Forwarded-For", ipHetzner)
	if d := e.evaluate(r); d.Action != ActionDeny {
		t.Errorf("X-Forwarded-For was trusted: %+v", d)
	}
	r = newRequest("10.0.0.1")
	r.RemoteAddr = ""
	if d := e.evaluate(r); d.Action != ActionDeny || d.Rule != -1 {
		t.Errorf("no address: %+v", d)
	}
}

func TestParseAddr(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1:80":          "192.0.2.1",
		"192.0.2.1":             "192.0.2.1",
		"[2001:db8::1]:443":     "2001:db8::1",
		"2001:db8::1":           "2001:db8::1",
		"[::ffff:192.0.2.1]:80": "192.0.2.1",
		"[fe80::1%eth0]:80":     "fe80::1",
		"[2001:db8::1]":         "2001:db8::1",
		"garbage":               "invalid IP",
		"":                      "invalid IP",
	} {
		if got := parseAddr(in).String(); got != want {
			t.Errorf("parseAddr(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestShadowWarningLogged(t *testing.T) {
	app, _ := newTestApp(t, &App{Groups: map[string]Selector{"staff": {IPs: []string{"10.8.0.0/16"}}}})
	core, logs := observer.New(zapcore.WarnLevel)
	p := Policy{Rules: []Rule{
		{Action: "allow", Selector: Selector{PrivateRanges: true}},
		{Action: "allow", Selector: Selector{Groups: []string{"staff"}}},
	}, Default: "deny"}
	if _, err := p.compile(app, zap.New(core)); err != nil {
		t.Fatal(err)
	}
	entries := logs.FilterMessageSnippet("can never match").All()
	if len(entries) != 1 || entries[0].ContextMap()["rule"] != int64(1) {
		t.Errorf("want one warning for rule 1, got %+v", entries)
	}
}

// There is only one real database per month, so these tests prove a swap by
// the loaded handle changing; TestReloadIPFile covers decisions changing.
func TestReloadDatabase(t *testing.T) {
	src := testDB(t, dbCountry)
	dir := t.TempDir()
	path := filepath.Join(dir, "country.mmdb")
	copyFile(t, src, path)

	app, logs := newTestApp(t, &App{DBCountry: path})
	p := Policy{Rules: []Rule{{Action: "allow", Selector: Selector{Countries: []string{"DE"}}}}, Default: "deny"}
	e, err := p.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	loaded := func() *dbHandle { return app.country.cur.Load() }
	failed := map[string]reloadFailure{}
	first := loaded()

	app.reloadOnce(failed)
	if loaded() != first {
		t.Error("unchanged file was reloaded")
	}

	replaceFile(t, src, path)
	app.reloadOnce(failed)
	second := loaded()
	if second == first {
		t.Fatal("replaced file was not reloaded")
	}
	if e.evaluate(newRequest(ipHetzner)).Action != ActionAllow {
		t.Error("reloaded database does not serve lookups")
	}
	if got := testutil.ToFloat64(app.metrics.reloads.WithLabelValues("country", "success")); got != 1 {
		t.Errorf("successful reloads = %v", got)
	}

	bad := filepath.Join(dir, "bad")
	writeFile(t, bad, "garbage")
	replaceFile(t, bad, path)
	app.reloadOnce(failed)
	app.reloadOnce(failed) // must not retry or log the same bad file again
	if loaded() != second {
		t.Error("bad file replaced the loaded database")
	}
	if e.evaluate(newRequest(ipHetzner)).Action != ActionAllow {
		t.Error("previous database stopped serving")
	}
	if got := testutil.ToFloat64(app.metrics.reloads.WithLabelValues("country", "error")); got != 1 {
		t.Errorf("failed reloads = %v, want 1", got)
	}
	if n := logs.FilterMessageSnippet("reload failed").Len(); n != 1 {
		t.Errorf("reload failure logged %d times, want 1", n)
	}

	replaceFile(t, testDB(t, dbASN), path)
	app.reloadOnce(failed)
	if loaded() != second {
		t.Error("wrong-type file replaced the loaded database")
	}

	replaceFile(t, src, path)
	app.reloadOnce(failed)
	if loaded() == second {
		t.Error("fixed file was not reloaded")
	}
}

func TestReloadIPFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "block.txt")
	writeFile(t, path, "192.0.2.0/24\n")

	app, _ := newTestApp(t, &App{Groups: map[string]Selector{"block": {IPFiles: []string{path}}}})
	p := Policy{Rules: []Rule{
		{Action: "deny", Selector: Selector{Groups: []string{"block"}}},
		{Action: "deny", Selector: Selector{IPFiles: []string{path}}},
	}, Default: "allow"}
	e, err := p.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if len(app.ipLists) != 1 {
		t.Errorf("ip_file loaded %d times, want once", len(app.ipLists))
	}
	decide := func(ip string) Action { return e.evaluate(newRequest(ip)).Action }
	failed := map[string]reloadFailure{}

	if decide("192.0.2.1") != ActionDeny || decide("198.51.100.1") != ActionAllow {
		t.Fatal("initial decisions wrong")
	}
	writeFile(t, filepath.Join(dir, "next"), "198.51.100.0/24\n")
	replaceFile(t, filepath.Join(dir, "next"), path)
	app.reloadOnce(failed)
	if decide("192.0.2.1") != ActionAllow || decide("198.51.100.1") != ActionDeny {
		t.Error("ip_file reload not picked up")
	}

	writeFile(t, filepath.Join(dir, "broken"), "198.51.100.0/24\nnope\n")
	replaceFile(t, filepath.Join(dir, "broken"), path)
	app.reloadOnce(failed)
	if decide("198.51.100.1") != ActionDeny {
		t.Error("broken ip_file: previous list must keep serving")
	}
	if got := testutil.ToFloat64(app.metrics.reloads.WithLabelValues("ip_file", "error")); got != 1 {
		t.Errorf("ip_file reload errors = %v, want 1", got)
	}

	os.Remove(path)
	app.reloadOnce(failed)
	if decide("198.51.100.1") != ActionDeny {
		t.Error("deleted ip_file: previous list must keep serving")
	}
}

func TestReloadLoop(t *testing.T) {
	src := testDB(t, dbCountry)
	path := filepath.Join(t.TempDir(), "country.mmdb")
	copyFile(t, src, path)

	app, _ := newTestApp(t, &App{DBCountry: path})
	// Below the minimum that Provision enforces, to keep the test fast.
	app.ReloadInterval = caddy.Duration(10 * time.Millisecond)
	p := Policy{Rules: []Rule{{Action: "allow", Selector: Selector{Countries: []string{"DE"}}}}, Default: "deny"}
	e, err := p.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	loaded := func() *dbHandle { return app.country.cur.Load() }
	first := loaded()
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}

	// Requests keep evaluating during the swap, for the race detector.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				if e.evaluate(newRequest(ipHetzner)).Action != ActionAllow {
					t.Error("lookup failed during reload")
					return
				}
			}
		}
	}()

	replaceFile(t, src, path)
	deadline := time.Now().Add(30 * time.Second)
	for loaded() == first {
		if time.Now().After(deadline) {
			t.Fatal("reload loop did not pick up the new database")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	<-done

	if err := app.Stop(); err != nil {
		t.Fatal(err)
	}
	second := loaded()
	replaceFile(t, src, path)
	time.Sleep(100 * time.Millisecond)
	if loaded() != second {
		t.Error("reload loop still running after Stop")
	}
}

func assertVars(t *testing.T, r *http.Request, want map[string]string) {
	t.Helper()
	for k, v := range want {
		got, _ := caddyhttp.GetVar(r.Context(), k).(string)
		if got != v {
			t.Errorf("var %s = %q, want %q", k, got, v)
		}
	}
}

func TestStartLogsSummary(t *testing.T) {
	path := testDB(t, dbCountry)
	app, logs := newTestApp(t, &App{DBCountry: path})
	p := Policy{Rules: []Rule{{Action: "allow", Selector: Selector{Countries: []string{"DE"}}}}, Default: "deny"}
	if _, err := p.compile(app, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}

	started := logs.FilterMessage("started").All()
	if len(started) != 1 {
		t.Fatalf("got %d started logs, want 1", len(started))
	}
	fields := started[0].ContextMap()
	if fields["db_country"] != path {
		t.Errorf("db_country = %v, want %s", fields["db_country"], path)
	}
	if fields["db_asn"] != "unused" {
		t.Errorf("db_asn = %v, want unused", fields["db_asn"])
	}
}
