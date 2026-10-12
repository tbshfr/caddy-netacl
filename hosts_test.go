package netacl

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

func TestHostSetLookup(t *testing.T) {
	s := newHostSet([]string{"example.com", "Shop.Example.com", "*.example.net", "{env.HOST}", "::1", "example.com", "*.*.example.org"})
	for reqHost, want := range map[string]string{
		"example.com":         "example.com",
		"EXAMPLE.com:8443":    "example.com",
		"shop.example.com":    "shop.example.com",
		"a.example.net":       "*.example.net",
		"A.example.net:443":   "*.example.net",
		"example.net":         otherHost, // * matches exactly one label
		"a.b.example.net":     otherHost,
		"[::1]:443":           "::1",
		"[::1]":               "::1",
		"::1":                 "::1",
		"a.b.example.org":     otherHost, // only *. wildcards are matched
		"b.example.org":       otherHost,
		"attacker.test":       otherHost,
		"{env.HOST}":          otherHost, // placeholders are never labels
		"":                    otherHost,
		"example.com.evil.io": otherHost,
	} {
		if got := s.lookup(reqHost).host; got != want {
			t.Errorf("lookup(%q) = %q, want %q", reqHost, got, want)
		}
	}
	if len(s.exact) != 3 || len(s.wildcards) != 1 {
		t.Errorf("got %d exact hosts and %d wildcards, want 3 and 1", len(s.exact), len(s.wildcards))
	}
}

func TestRouteHosts(t *testing.T) {
	inner := &caddyhttp.MatchHost{"api.example.com"}
	app := &caddyhttp.App{Servers: map[string]*caddyhttp.Server{
		"srv0": {
			Routes: caddyhttp.RouteList{
				{
					MatcherSets: caddyhttp.MatcherSets{{&caddyhttp.MatchHost{"example.com", "*.example.net"}}},
					Handlers: []caddyhttp.MiddlewareHandler{&caddyhttp.Subroute{Routes: caddyhttp.RouteList{
						{MatcherSets: caddyhttp.MatcherSets{{inner, caddyhttp.MatchPath{"/api"}}}},
					}}},
				},
				{MatcherSets: caddyhttp.MatcherSets{{caddyhttp.MatchPath{"/"}}}},
			},
			Errors: &caddyhttp.HTTPErrorConfig{Routes: caddyhttp.RouteList{
				{MatcherSets: caddyhttp.MatcherSets{{&caddyhttp.MatchHost{"errors.example.com"}}}},
			}},
		},
	}}
	got := routeHosts(app)
	slices.Sort(got)
	want := []string{"*.example.net", "api.example.com", "errors.example.com", "example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("routeHosts = %v, want %v", got, want)
	}
}

func TestPerHostMetrics(t *testing.T) {
	app, _ := newTestApp(t, &App{PerHostMetrics: true, DBCountry: testDB(t, dbCountry)})
	app.metrics.listHosts = func() []string { return []string{"example.com", "*.example.net"} }
	p := Policy{Rules: []Rule{
		{Action: "allow", Selector: Selector{Countries: []string{"DE"}}},
	}, Default: "deny"}
	e, err := p.compile(app, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is exported before a host's first request.
	if got := testutil.CollectAndCount(app.metrics.decisions); got != 0 {
		t.Errorf("%d decision series before any request, want 0", got)
	}

	request := func(host, ip string) {
		r := newRequest(ip)
		r.Host = host
		e.evaluate(r)
	}
	request("example.com", ipHetzner)
	request("Example.com:443", ipGoogle)
	request("a.example.net", ipHetzner)
	request("attacker.test", ipHetzner)
	request("other.test", ipHetzner)

	for _, tc := range []struct {
		c      *prometheus.CounterVec
		labels []string
		want   float64
	}{
		{app.metrics.decisions, []string{"allow", "example.com"}, 1},
		{app.metrics.decisions, []string{"deny", "example.com"}, 1},
		{app.metrics.decisions, []string{"allow", "*.example.net"}, 1},
		{app.metrics.decisions, []string{"deny", "*.example.net"}, 0},
		{app.metrics.decisions, []string{"allow", otherHost}, 2},
		{app.metrics.lookups, []string{"country", "hit", "example.com"}, 2},
		{app.metrics.lookups, []string{"country", "hit", otherHost}, 2},
	} {
		if got := testutil.ToFloat64(tc.c.WithLabelValues(tc.labels...)); got != tc.want {
			t.Errorf("%v = %v, want %v", tc.labels, got, tc.want)
		}
	}
	// 3 hosts with 2 decisions each, all created on the host's first request.
	if got := testutil.CollectAndCount(app.metrics.decisions); got != 6 {
		t.Errorf("%d decision series, want 6", got)
	}
}

func TestPerHostMetricsWithoutHTTPApp(t *testing.T) {
	app, _ := newTestApp(t, &App{PerHostMetrics: true})
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if got := app.metrics.forRequest(r); got != app.metrics.hosts.other.c {
		t.Error("without an http app, every host should be counted as " + otherHost)
	}
}
