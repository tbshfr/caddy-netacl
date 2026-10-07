package netacl

import (
	"slices"
	"strings"
	"testing"
)

func TestResolveGroupsNesting(t *testing.T) {
	gs, err := resolveGroups(map[string]Selector{
		"a":   {IPs: []string{"192.0.2.1"}, Groups: []string{"b"}},
		"b":   {ASNs: []uint32{64496}, Groups: []string{"c"}},
		"c":   {Countries: []string{"de"}, Continents: []string{"eu"}, IPFiles: []string{"/x"}},
		"top": {Groups: []string{"a", "c"}, PrivateRanges: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := gs.lookup("a")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.prefixes) != 1 || !slices.Equal(a.asns, []uint32{64496}) ||
		!slices.Equal(a.countries, []string{"DE"}) || !slices.Equal(a.continents, []string{"EU"}) ||
		!slices.Equal(a.ipFiles, []string{"/x"}) {
		t.Errorf("a not flattened: %+v", a)
	}
	top, _ := gs.lookup("top")
	if len(top.prefixes) < 2 || len(top.asns) != 1 {
		t.Errorf("top not flattened: %+v", top)
	}
	// flattening must not alias the definitions of other groups
	c, _ := gs.lookup("c")
	if len(c.prefixes) != 0 || len(c.asns) != 0 {
		t.Errorf("c was modified: %+v", c)
	}
}

func TestResolveGroupsErrors(t *testing.T) {
	tests := []struct {
		name string
		defs map[string]Selector
		want string
	}{
		{"cycle", map[string]Selector{
			"a": {Groups: []string{"b"}},
			"b": {Groups: []string{"a"}},
		}, "group cycle: a -> b -> a"},
		{"self cycle", map[string]Selector{
			"a": {Groups: []string{"a"}},
		}, "group cycle: a -> a"},
		{"long cycle", map[string]Selector{
			"a": {IPs: []string{"192.0.2.1"}, Groups: []string{"b"}},
			"b": {Groups: []string{"c"}},
			"c": {Groups: []string{"b"}},
		}, "group cycle: b -> c -> b"},
		{"unknown", map[string]Selector{
			"a": {Groups: []string{"missing"}},
		}, `group "a": unknown group @missing`},
		{"empty", map[string]Selector{
			"a": {},
		}, `group "a": no members`},
		{"bad member", map[string]Selector{
			"a": {IPs: []string{"nope"}},
		}, `group "a": invalid IP or CIDR "nope"`},
		{"bad name", map[string]Selector{
			"a b": {IPs: []string{"192.0.2.1"}},
		}, "invalid group name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveGroups(tc.defs)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestGroupMixedTypesInRule(t *testing.T) {
	rs := mustCompile(t, map[string]Selector{
		"mixed": {IPs: []string{"192.0.2.0/24"}, ASNs: []uint32{3320}, Continents: []string{"NA"}},
	}, []Rule{
		{Action: "allow", Selector: Selector{Groups: []string{"mixed"}}},
	}, "deny")
	for ip, want := range map[string]Action{
		"192.0.2.5": ActionAllow, // ip
		"5.0.0.1":   ActionAllow, // asn
		"8.8.8.8":   ActionAllow, // continent
		"7.7.7.7":   ActionDeny,
	} {
		if got := eval(rs, newFakeGeo(), ip).Action; got != want {
			t.Errorf("%s: got %s, want %s", ip, got, want)
		}
	}
	if rs.needs != needCountry|needASN {
		t.Errorf("needs = %b, want country|asn", rs.needs)
	}
}
