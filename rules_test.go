package netacl

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeGeo struct {
	countries map[string]countryResult
	asns      map[string]uint32
	err       error
	calls     map[string]int
}

func (f *fakeGeo) lookupCountry(addr netip.Addr) (countryResult, error) {
	f.count("country")
	if f.err != nil {
		return countryResult{}, f.err
	}
	for k, v := range f.countries {
		if netip.MustParsePrefix(k).Contains(addr) {
			return v, nil
		}
	}
	return countryResult{}, nil
}

func (f *fakeGeo) lookupASN(addr netip.Addr) (asnResult, error) {
	f.count("asn")
	if f.err != nil {
		return asnResult{}, f.err
	}
	for k, v := range f.asns {
		if netip.MustParsePrefix(k).Contains(addr) {
			return asnResult{found: true, asn: v}, nil
		}
	}
	return asnResult{}, nil
}

func (f *fakeGeo) count(db string) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[db]++
}

func newFakeGeo() *fakeGeo {
	return &fakeGeo{
		countries: map[string]countryResult{
			"5.0.0.0/16":     {found: true, country: "DE", continent: "EU"},
			"8.8.8.0/24":     {found: true, country: "US", continent: "NA"},
			"7.7.7.0/24":     {continent: "EU"},
			"2a00:1450::/32": {found: true, country: "DE", continent: "EU"},
		},
		asns: map[string]uint32{
			"5.0.0.0/16": 3320,
			"8.8.8.0/24": 15169,
		},
	}
}

func noFiles(path string) (*ipList, error) {
	return nil, errors.New("no ip_files in this test")
}

func mustCompile(t *testing.T, groups map[string]Selector, rules []Rule, def string) *ruleset {
	t.Helper()
	gs, err := resolveGroups(groups)
	if err != nil {
		t.Fatalf("resolveGroups: %v", err)
	}
	rs, err := compileRules(rules, def, gs.lookup, noFiles)
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}
	return rs
}

func eval(rs *ruleset, src geoSource, ip string) Decision {
	var addr netip.Addr
	if ip != "" {
		addr = netip.MustParseAddr(ip).Unmap()
	}
	return rs.evaluate(&lookupState{addr: addr}, src, nil)
}

func TestEvaluate(t *testing.T) {
	groups := map[string]Selector{
		"office":   {IPs: []string{"203.0.113.0/24", "198.51.100.7"}},
		"vpn":      {IPs: []string{"10.8.0.0/16"}},
		"staff":    {Groups: []string{"office", "vpn"}},
		"badhosts": {ASNs: []uint32{15169}},
		"friendly": {Countries: []string{"DE", "SE"}},
	}
	rules := []Rule{
		{Action: "allow", Selector: Selector{Groups: []string{"staff"}}},
		{Action: "deny", Selector: Selector{Groups: []string{"badhosts"}}},
		{Action: "allow", Selector: Selector{Groups: []string{"friendly"}}},
		{Action: "allow", Selector: Selector{IPs: []string{"192.0.2.10"}}},
		{Action: "deny", Selector: Selector{Countries: []string{"UNK"}}},
		{Action: "allow", Selector: Selector{Continents: []string{"NA"}}},
	}
	rs := mustCompile(t, groups, rules, "deny")

	tests := []struct {
		ip     string
		action Action
		rule   int
	}{
		{"203.0.113.9", ActionAllow, 0},    // office via staff
		{"198.51.100.7", ActionAllow, 0},   // single IP in group
		{"198.51.100.8", ActionDeny, 4},    // public but not in the country DB: UNK
		{"10.8.1.1", ActionAllow, 0},       // vpn via staff
		{"8.8.8.8", ActionDeny, 1},         // ASN 15169 denied before continent NA allow
		{"5.0.1.2", ActionAllow, 2},        // DE
		{"2a00:1450::1", ActionAllow, 2},   // DE over IPv6
		{"::ffff:5.0.1.2", ActionAllow, 2}, // IPv4-mapped is unmapped
		{"192.0.2.10", ActionAllow, 3},     // explicit ip
		{"7.7.7.7", ActionDeny, 4},         // continent only, no country -> UNK
		{"10.9.9.9", ActionDeny, -1},       // private: no geo, UNK does not match
		{"", ActionDeny, -1},               // no client IP
		{"::1", ActionDeny, -1},            // loopback
		{"fe80::1", ActionDeny, -1},        // link-local
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			d := eval(rs, newFakeGeo(), tc.ip)
			if d.Action != tc.action || d.Rule != tc.rule {
				t.Errorf("got %s rule %d, want %s rule %d", d.Action, d.Rule, tc.action, tc.rule)
			}
		})
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	rs := mustCompile(t, nil, []Rule{
		{Action: "deny", Selector: Selector{IPs: []string{"10.0.0.0/8"}}},
		{Action: "allow", Selector: Selector{IPs: []string{"10.1.0.0/16"}}},
	}, "allow")
	if d := eval(rs, newFakeGeo(), "10.1.2.3"); d.Action != ActionDeny || d.Rule != 0 {
		t.Errorf("got %+v, want deny by rule 0", d)
	}
}

func TestEvaluateDefaultAllow(t *testing.T) {
	rs := mustCompile(t, nil, []Rule{
		{Action: "deny", Selector: Selector{IPs: []string{"10.0.0.0/8"}}},
	}, "allow")
	if d := eval(rs, newFakeGeo(), "11.0.0.1"); d.Action != ActionAllow || d.Rule != -1 {
		t.Errorf("got %+v, want default allow", d)
	}
}

func TestEvaluateOrWithinRule(t *testing.T) {
	rs := mustCompile(t, nil, []Rule{
		{Action: "allow", Selector: Selector{IPs: []string{"192.0.2.1"}, ASNs: []uint32{3320}, Countries: []string{"US"}}},
	}, "deny")
	for _, ip := range []string{"192.0.2.1", "5.0.0.1", "8.8.8.8"} {
		if d := eval(rs, newFakeGeo(), ip); d.Action != ActionAllow {
			t.Errorf("%s: got %s, want allow", ip, d.Action)
		}
	}
	if d := eval(rs, newFakeGeo(), "7.7.7.7"); d.Action != ActionDeny {
		t.Errorf("7.7.7.7: got %s, want deny", d.Action)
	}
}

func TestPrivateRanges(t *testing.T) {
	rs := mustCompile(t, nil, []Rule{
		{Action: "allow", Selector: Selector{PrivateRanges: true}},
	}, "deny")
	for ip, want := range map[string]Action{
		"10.1.2.3":    ActionAllow,
		"172.16.0.1":  ActionAllow,
		"192.168.1.1": ActionAllow,
		"127.0.0.1":   ActionAllow,
		"::1":         ActionAllow,
		"fd12::1":     ActionAllow,
		"8.8.8.8":     ActionDeny,
	} {
		if d := eval(rs, newFakeGeo(), ip); d.Action != want {
			t.Errorf("%s: got %s, want %s", ip, d.Action, want)
		}
	}
}

func TestLookupsAreLazyAndCached(t *testing.T) {
	rs := mustCompile(t, nil, []Rule{
		{Action: "allow", Selector: Selector{IPs: []string{"5.0.0.1"}}},
		{Action: "deny", Selector: Selector{Countries: []string{"FR"}}},
		{Action: "deny", Selector: Selector{Continents: []string{"AF"}}},
		{Action: "deny", Selector: Selector{ASNs: []uint32{1}}},
		{Action: "allow", Selector: Selector{Countries: []string{"DE"}}},
	}, "deny")

	geo := newFakeGeo()
	eval(rs, geo, "5.0.0.1")
	if len(geo.calls) != 0 {
		t.Errorf("IP match did lookups: %v", geo.calls)
	}

	geo = newFakeGeo()
	ls := &lookupState{addr: netip.MustParseAddr("5.0.0.2")}
	d := rs.evaluate(ls, geo, nil)
	if d.Action != ActionAllow || d.Rule != 4 {
		t.Errorf("got %+v", d)
	}
	if geo.calls["country"] != 1 || geo.calls["asn"] != 1 {
		t.Errorf("want one lookup per database, got %v", geo.calls)
	}
	rs.evaluate(ls, geo, nil)
	if geo.calls["country"] != 1 || geo.calls["asn"] != 1 {
		t.Errorf("cache not reused: %v", geo.calls)
	}

	geo = newFakeGeo()
	eval(rs, geo, "10.0.0.1")
	if len(geo.calls) != 0 {
		t.Errorf("private address was looked up: %v", geo.calls)
	}
}

func TestLookupErrorMatchesNothing(t *testing.T) {
	rs := mustCompile(t, nil, []Rule{
		{Action: "deny", Selector: Selector{Countries: []string{"UNK"}}},
		{Action: "deny", Selector: Selector{ASNs: []uint32{3320}}},
	}, "allow")
	geo := newFakeGeo()
	geo.err = errors.New("boom")
	if d := eval(rs, geo, "5.0.0.1"); d.Action != ActionAllow || d.Rule != -1 {
		t.Errorf("got %+v, want default", d)
	}
}

func TestLookupErrorDeny(t *testing.T) {
	rs := mustCompile(t, nil, []Rule{
		{Action: "allow", Selector: Selector{IPs: []string{"5.0.0.1"}}},
		{Action: "allow", Selector: Selector{Countries: []string{"DE"}}},
	}, "allow")
	rs.denyOnLookupError = true
	geo := newFakeGeo()
	geo.err = errors.New("boom")
	if d := eval(rs, geo, "5.0.0.2"); d.Action != ActionDeny || d.Rule != ruleLookupError {
		t.Errorf("got %+v, want deny by lookup error", d)
	}
	// Rules decided before any lookup are unaffected.
	if d := eval(rs, geo, "5.0.0.1"); d.Action != ActionAllow || d.Rule != 0 {
		t.Errorf("got %+v, want rule 0", d)
	}
	// Private addresses are never looked up, so they cannot fail.
	if d := eval(rs, geo, "10.0.0.1"); d.Action != ActionAllow || d.Rule != ruleDefault {
		t.Errorf("got %+v, want default", d)
	}
}

func TestLookupErrorOtherSelectorStillMatches(t *testing.T) {
	rs := mustCompile(t, nil, []Rule{
		{Action: "allow", Selector: Selector{Countries: []string{"DE"}, ASNs: []uint32{3320}}},
	}, "deny")
	rs.denyOnLookupError = true
	geo := &failingCountry{fakeGeo: newFakeGeo()}
	if d := eval(rs, geo, "5.0.0.1"); d.Action != ActionAllow || d.Rule != 0 {
		t.Errorf("got %+v, want the ASN selector to match", d)
	}
}

type failingCountry struct{ *fakeGeo }

func (f *failingCountry) lookupCountry(netip.Addr) (countryResult, error) {
	return countryResult{}, errors.New("boom")
}

func TestLogThrottle(t *testing.T) {
	lt := &logThrottle{every: time.Minute}
	now := time.Now()
	if ok, n := lt.allow(now); !ok || n != 0 {
		t.Fatalf("first entry: %v, %d", ok, n)
	}
	for range 3 {
		if ok, _ := lt.allow(now.Add(time.Second)); ok {
			t.Fatal("entry within the interval was let through")
		}
	}
	if ok, n := lt.allow(now.Add(time.Minute)); !ok || n != 3 {
		t.Errorf("after the interval: %v, %d suppressed, want true, 3", ok, n)
	}
}

func TestIPFileSelector(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	writeFile(t, path, "# blocklist\n192.0.2.0/24\n\n  2001:db8::1  # one host\n")
	d, err := loadIPList(path)
	if err != nil {
		t.Fatal(err)
	}
	l := &ipList{path: path}
	l.cur.Store(d)
	files := func(p string) (*ipList, error) { return l, nil }

	rs, err := compileRules([]Rule{
		{Action: "deny", Selector: Selector{IPFiles: []string{path}}},
	}, "allow", (*groupSet)(nil).lookup, files)
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]Action{
		"192.0.2.77":  ActionDeny,
		"2001:db8::1": ActionDeny,
		"2001:db8::2": ActionAllow,
	} {
		if got := eval(rs, newFakeGeo(), ip).Action; got != want {
			t.Errorf("%s: got %s, want %s", ip, got, want)
		}
	}

	writeFile(t, path, "198.51.100.0/24\n")
	d, err = loadIPList(path)
	if err != nil {
		t.Fatal(err)
	}
	l.cur.Store(d)
	if got := eval(rs, newFakeGeo(), "192.0.2.77").Action; got != ActionAllow {
		t.Errorf("after swap: got %s, want allow", got)
	}
}

func TestLoadIPListErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.txt")
	writeFile(t, path, "192.0.2.0/24\nnot-an-ip\n")
	_, err := loadIPList(path)
	if err == nil || !strings.Contains(err.Error(), "bad.txt:2") {
		t.Errorf("want error with line number, got %v", err)
	}
	if _, err := loadIPList(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("want error for missing file")
	}
	if _, err := loadIPList(dir); err == nil {
		t.Error("want error for directory")
	}
}

func TestCompileErrors(t *testing.T) {
	gs, _ := resolveGroups(map[string]Selector{"ok": {IPs: []string{"192.0.2.1"}}})
	tests := []struct {
		name  string
		rules []Rule
		def   string
		want  string
	}{
		{"missing default", nil, "", "missing default"},
		{"bad default", nil, "maybe", "invalid action"},
		{"bad action", []Rule{{Action: "permit", Selector: Selector{IPs: []string{"1.2.3.4"}}}}, "deny", "invalid action"},
		{"empty rule", []Rule{{Action: "allow"}}, "deny", "no selectors"},
		{"bad ip", []Rule{{Action: "allow", Selector: Selector{IPs: []string{"1.2.3.999"}}}}, "deny", "invalid IP or CIDR"},
		{"bad cidr", []Rule{{Action: "allow", Selector: Selector{IPs: []string{"1.2.3.0/33"}}}}, "deny", "invalid IP or CIDR"},
		{"asn 0", []Rule{{Action: "allow", Selector: Selector{ASNs: []uint32{0}}}}, "deny", "invalid ASN 0"},
		{"bad country", []Rule{{Action: "allow", Selector: Selector{Countries: []string{"DEU"}}}}, "deny", "invalid country code"},
		{"bad continent", []Rule{{Action: "allow", Selector: Selector{Continents: []string{"XX"}}}}, "deny", "invalid continent code"},
		{"unknown group", []Rule{{Action: "allow", Selector: Selector{Groups: []string{"nope"}}}}, "deny", "unknown group @nope"},
		{"ip_file error", []Rule{{Action: "allow", Selector: Selector{IPFiles: []string{"x"}}}}, "deny", "no ip_files"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileRules(tc.rules, tc.def, gs.lookup, noFiles)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestParsers(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":            "192.0.2.1/32",
		"192.0.2.77/24":        "192.0.2.0/24",
		"2001:db8::1":          "2001:db8::1/128",
		"::ffff:192.0.2.1":     "192.0.2.1/32",
		"::ffff:192.0.2.0/120": "192.0.2.0/24",
		"fe80::1%eth0":         "fe80::1/128",
		"127.0.0.1/8":          "127.0.0.0/8",
	} {
		p, err := ParsePrefix(in)
		if err != nil || p.String() != want {
			t.Errorf("ParsePrefix(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for in, want := range map[string]uint32{"64496": 64496, "AS64496": 64496, "as1": 1, "4294967295": 4294967295} {
		if got, err := ParseASN(in); err != nil || got != want {
			t.Errorf("ParseASN(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "AS", "-1", "4294967296", "AS 1", "1.5", "0", "AS0"} {
		if _, err := ParseASN(in); err == nil {
			t.Errorf("ParseASN(%q): want error", in)
		}
	}
	for in, want := range map[string]string{"de": "DE", "Se": "SE", "unk": "UNK"} {
		if got, err := ParseCountry(in); err != nil || got != want {
			t.Errorf("ParseCountry(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "D", "DEU", "D1", "ü1"} {
		if _, err := ParseCountry(in); err == nil {
			t.Errorf("ParseCountry(%q): want error", in)
		}
	}
	if got, err := ParseContinent("eu"); err != nil || got != "EU" {
		t.Errorf("ParseContinent(eu) = %q, %v", got, err)
	}
}

func TestShadowedRules(t *testing.T) {
	groups := map[string]Selector{
		"staff": {IPs: []string{"10.8.0.0/16", "192.168.1.0/24"}},
	}
	rs := mustCompile(t, groups, []Rule{
		{Action: "allow", Selector: Selector{PrivateRanges: true}},
		{Action: "allow", Selector: Selector{Groups: []string{"staff"}}},                   // 1: all private
		{Action: "deny", Selector: Selector{Countries: []string{"DE"}}},                    // 2: new
		{Action: "allow", Selector: Selector{Countries: []string{"DE"}}},                   // 3: covered by 2
		{Action: "deny", Selector: Selector{Countries: []string{"DE", "FR"}}},              // 4: FR is new
		{Action: "deny", Selector: Selector{IPs: []string{"8.8.8.8"}, ASNs: []uint32{1}}},  // 5: new
		{Action: "deny", Selector: Selector{IPs: []string{"10.0.0.1"}, ASNs: []uint32{1}}}, // 6: covered
	}, "deny")
	got := rs.shadowedRules()
	want := []int{1, 3, 6}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
