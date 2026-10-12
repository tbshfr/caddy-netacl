package netacl

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"

	"go.uber.org/zap"
)

func randomPrefixes(n int) []string {
	rng := rand.New(rand.NewPCG(1, 2))
	seen := make(map[string]bool, n)
	out := make([]string, 0, n)
	for len(out) < n {
		a := netip.AddrFrom4([4]byte{byte(11 + rng.IntN(150)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))})
		bits := 24
		if rng.IntN(2) == 0 {
			bits = 32
		}
		s := netip.PrefixFrom(a, bits).Masked().String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func BenchmarkEvaluate(b *testing.B) {
	for _, n := range []int{10, 1000, 100000} {
		for _, geo := range []bool{false, true} {
			name := fmt.Sprintf("prefixes=%d/geo=%v", n, geo)
			b.Run(name, func(b *testing.B) {
				app, _ := newTestApp(b, &App{DBCountry: testDB(b, dbCountry), DBASN: testDB(b, dbASN)})
				app.logger = zap.NewNop()
				rules := []Rule{
					{Action: "deny", Selector: Selector{IPs: randomPrefixes(n)}},
				}
				if geo {
					rules = append(rules,
						Rule{Action: "deny", Selector: Selector{ASNs: []uint32{64496}}},
						Rule{Action: "allow", Selector: Selector{Countries: []string{"DE", "SE", "NO"}}},
					)
				}
				p := Policy{Rules: rules, Default: "deny"}
				e, err := p.compile(app, zap.NewNop())
				if err != nil {
					b.Fatal(err)
				}
				// The random prefixes start at 11.0.0.0, so every rule is evaluated.
				addr := netip.MustParseAddr(ipHetzner)
				r := newRequest(ipHetzner)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					ls := &lookupState{addr: addr}
					d := e.rs.evaluate(ls, e.src, func(db string, addr netip.Addr, result string, err error) {
						e.observeLookup(e.metrics.all, db, addr, result, err)
					})
					setDecisionVars(r, d, ls)
				}
			})
		}
	}
}

func BenchmarkEvaluatePerHost(b *testing.B) {
	hosts := make([]string, 0, 1100)
	for i := range 1000 {
		hosts = append(hosts, fmt.Sprintf("site%d.example.com", i))
	}
	for i := range 100 {
		hosts = append(hosts, fmt.Sprintf("*.zone%d.example.net", i))
	}
	for _, tc := range []struct {
		name    string
		perHost bool
		host    string
	}{
		{"perHost=false", false, "site500.example.com"},
		{"perHost=true/exact", true, "site500.example.com"},
		{"perHost=true/wildcard", true, "a.zone99.example.net"},
		{"perHost=true/other", true, "attacker.test"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			app, _ := newTestApp(b, &App{PerHostMetrics: tc.perHost})
			app.logger = zap.NewNop()
			app.metrics.listHosts = func() []string { return hosts }
			p := Policy{Rules: []Rule{
				{Action: "deny", Selector: Selector{IPs: randomPrefixes(1000)}},
			}, Default: "allow"}
			e, err := p.compile(app, zap.NewNop())
			if err != nil {
				b.Fatal(err)
			}
			r := newRequest(ipHetzner)
			r.Host = tc.host
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				e.evaluate(r)
			}
		})
	}
}
