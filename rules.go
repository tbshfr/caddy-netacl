package netacl

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gaissmai/bart"
)

type Action uint8

const (
	ActionAllow Action = iota + 1
	ActionDeny
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	}
	return "invalid"
}

func ParseAction(s string) (Action, error) {
	switch s {
	case "allow":
		return ActionAllow, nil
	case "deny":
		return ActionDeny, nil
	}
	return 0, fmt.Errorf("invalid action %q: must be allow or deny", s)
}

// UnknownCountry matches public addresses that have no country in the
// database.
const UnknownCountry = "UNK"

var validContinents = map[string]struct{}{
	"AF": {}, "AN": {}, "AS": {}, "EU": {}, "NA": {}, "OC": {}, "SA": {},
}

// Selector is used for both groups and rules. All of its fields are OR'd.
type Selector struct {
	// Group names without the leading @.
	Groups []string `json:"groups,omitempty"`
	IPs    []string `json:"ips,omitempty"`
	// Files with one IP or CIDR per line; blank lines and text after # are
	// ignored. They are re-read on the app's reload_interval.
	IPFiles       []string `json:"ip_files,omitempty"`
	PrivateRanges bool     `json:"private_ranges,omitempty"`
	ASNs          []uint32 `json:"asns,omitempty"`
	// ISO 3166-1 alpha-2 codes, or UNK.
	Countries []string `json:"countries,omitempty"`
	// AF, AN, AS, EU, NA, OC or SA.
	Continents []string `json:"continents,omitempty"`
}

func (s Selector) isEmpty() bool {
	return len(s.Groups) == 0 && len(s.IPs) == 0 && len(s.IPFiles) == 0 &&
		!s.PrivateRanges && len(s.ASNs) == 0 && len(s.Countries) == 0 && len(s.Continents) == 0
}

type Rule struct {
	// allow or deny
	Action string `json:"action"`
	Selector
}

type spec struct {
	prefixes   []netip.Prefix
	ipFiles    []string
	asns       []uint32
	countries  []string
	continents []string
}

func (s *spec) merge(o *spec) {
	s.prefixes = append(s.prefixes, o.prefixes...)
	s.ipFiles = append(s.ipFiles, o.ipFiles...)
	s.asns = append(s.asns, o.asns...)
	s.countries = append(s.countries, o.countries...)
	s.continents = append(s.continents, o.continents...)
}

func parseSpec(sel Selector) (*spec, []string, error) {
	sp := new(spec)
	for _, s := range sel.IPs {
		p, err := ParsePrefix(s)
		if err != nil {
			return nil, nil, err
		}
		sp.prefixes = append(sp.prefixes, p)
	}
	if sel.PrivateRanges {
		for _, s := range caddyhttp.PrivateRangesCIDR() {
			p, err := ParsePrefix(s)
			if err != nil {
				return nil, nil, fmt.Errorf("private_ranges: %w", err)
			}
			sp.prefixes = append(sp.prefixes, p)
		}
	}
	for _, f := range sel.IPFiles {
		if f == "" {
			return nil, nil, errors.New("empty ip_file path")
		}
		sp.ipFiles = append(sp.ipFiles, f)
	}
	for _, a := range sel.ASNs {
		if a == 0 {
			return nil, nil, errASNZero
		}
		sp.asns = append(sp.asns, a)
	}
	for _, c := range sel.Countries {
		cc, err := ParseCountry(c)
		if err != nil {
			return nil, nil, err
		}
		sp.countries = append(sp.countries, cc)
	}
	for _, c := range sel.Continents {
		cc, err := ParseContinent(c)
		if err != nil {
			return nil, nil, err
		}
		sp.continents = append(sp.continents, cc)
	}
	for _, g := range sel.Groups {
		if err := validateGroupName(g); err != nil {
			return nil, nil, err
		}
	}
	return sp, sel.Groups, nil
}

func ParsePrefix(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR %q", s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR %q", s)
		}
		a = a.WithZone("")
		p = netip.PrefixFrom(a, a.BitLen())
	}
	// Client addresses are unmapped before matching, so configured
	// IPv4-mapped prefixes must be unmapped too or they could never match.
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR %q: IPv4-mapped prefix shorter than /96", s)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

func ParseASN(s string) (uint32, error) {
	n := s
	if len(n) > 2 && strings.EqualFold(n[:2], "AS") {
		n = n[2:]
	}
	v, err := strconv.ParseUint(n, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid ASN %q: must be a 32-bit unsigned number, optionally prefixed with AS", s)
	}
	if v == 0 {
		return 0, errASNZero
	}
	return uint32(v), nil
}

// ASN 0 is reserved, and lookups report entries without an ASN as not found,
// so a selector for it could never match.
var errASNZero = errors.New("invalid ASN 0: it is reserved and never matches")

func ParseCountry(s string) (string, error) {
	u := strings.ToUpper(s)
	if u == UnknownCountry {
		return u, nil
	}
	if len(u) != 2 || u[0] < 'A' || u[0] > 'Z' || u[1] < 'A' || u[1] > 'Z' {
		return "", fmt.Errorf("invalid country code %q: must be two letters (ISO 3166-1 alpha-2) or UNK", s)
	}
	return u, nil
}

func ParseContinent(s string) (string, error) {
	u := strings.ToUpper(s)
	if _, ok := validContinents[u]; !ok {
		return "", fmt.Errorf("invalid continent code %q: must be one of AF, AN, AS, EU, NA, OC, SA", s)
	}
	return u, nil
}

type need uint8

const (
	needCountry need = 1 << iota
	needASN
)

type matchSet struct {
	prefixes   *bart.Lite
	ipFiles    []*ipList
	asns       map[uint32]struct{}
	countries  map[string]struct{}
	continents map[string]struct{}
}

type ipListSource func(path string) (*ipList, error)

func compileSet(sp *spec, files ipListSource) (*matchSet, error) {
	m := new(matchSet)
	if len(sp.prefixes) > 0 {
		m.prefixes = new(bart.Lite)
		for _, p := range sp.prefixes {
			m.prefixes.Insert(p)
		}
	}
	for _, path := range sp.ipFiles {
		l, err := files(path)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(m.ipFiles, l) {
			m.ipFiles = append(m.ipFiles, l)
		}
	}
	if len(sp.asns) > 0 {
		m.asns = make(map[uint32]struct{}, len(sp.asns))
		for _, a := range sp.asns {
			m.asns[a] = struct{}{}
		}
	}
	if len(sp.countries) > 0 {
		m.countries = make(map[string]struct{}, len(sp.countries))
		for _, c := range sp.countries {
			m.countries[c] = struct{}{}
		}
	}
	if len(sp.continents) > 0 {
		m.continents = make(map[string]struct{}, len(sp.continents))
		for _, c := range sp.continents {
			m.continents[c] = struct{}{}
		}
	}
	return m, nil
}

func (m *matchSet) needs() need {
	var n need
	if len(m.countries) > 0 || len(m.continents) > 0 {
		n |= needCountry
	}
	if len(m.asns) > 0 {
		n |= needASN
	}
	return n
}

func (m *matchSet) matchIP(addr netip.Addr) bool {
	if m.prefixes != nil && m.prefixes.Contains(addr) {
		return true
	}
	for _, l := range m.ipFiles {
		if l.contains(addr) {
			return true
		}
	}
	return false
}

// Implementations must be safe for concurrent use.
type geoSource interface {
	lookupCountry(addr netip.Addr) (countryResult, error)
	lookupASN(addr netip.Addr) (asnResult, error)
}

type countryResult struct {
	found     bool
	country   string
	continent string // may be set even when country is not
}

type asnResult struct {
	found bool
	asn   uint32
}

// lookupState is shared by all netacl instances on a request, so each
// database is queried at most once per request.
type lookupState struct {
	addr netip.Addr

	countryDone bool
	countryErr  bool
	country     countryResult

	asnDone bool
	asnErr  bool
	asn     asnResult
}

type lookupObserver func(db string, addr netip.Addr, result string, err error)

func (ls *lookupState) ensureCountry(src geoSource, obs lookupObserver) {
	if ls.countryDone {
		return
	}
	ls.countryDone = true
	r, err := src.lookupCountry(ls.addr)
	result := "hit"
	switch {
	case err != nil:
		ls.countryErr = true
		result = "error"
	case !r.found:
		result = "miss"
	}
	ls.country = r
	if obs != nil {
		obs("country", ls.addr, result, err)
	}
}

func (ls *lookupState) ensureASN(src geoSource, obs lookupObserver) {
	if ls.asnDone {
		return
	}
	ls.asnDone = true
	r, err := src.lookupASN(ls.addr)
	result := "hit"
	switch {
	case err != nil:
		ls.asnErr = true
		result = "error"
	case !r.found:
		result = "miss"
	}
	ls.asn = r
	if obs != nil {
		obs("asn", ls.addr, result, err)
	}
}

// Non-public addresses are never in the databases. Skipping them saves the
// lookups and keeps "country UNK" from matching internal clients.
func geoEligible(addr netip.Addr) bool {
	return addr.IsValid() && !addr.IsPrivate() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() && !addr.IsUnspecified()
}

// match reports whether any selector matches, and whether a selector could
// not be checked because its database lookup failed.
func (m *matchSet) match(ls *lookupState, src geoSource, obs lookupObserver) (matched, lookupFailed bool) {
	addr := ls.addr
	if !addr.IsValid() {
		return false, false
	}
	if m.matchIP(addr) {
		return true, false
	}
	if !geoEligible(addr) {
		return false, false
	}
	if len(m.countries) > 0 || len(m.continents) > 0 {
		ls.ensureCountry(src, obs)
		if ls.countryErr {
			lookupFailed = true
		} else {
			c := ls.country
			if c.found {
				if _, ok := m.countries[c.country]; ok {
					return true, false
				}
			} else if _, ok := m.countries[UnknownCountry]; ok {
				return true, false
			}
			if c.continent != "" {
				if _, ok := m.continents[c.continent]; ok {
					return true, false
				}
			}
		}
	}
	if len(m.asns) > 0 {
		ls.ensureASN(src, obs)
		if ls.asnErr {
			lookupFailed = true
		} else if ls.asn.found {
			if _, ok := m.asns[ls.asn.asn]; ok {
				return true, false
			}
		}
	}
	return false, lookupFailed
}

type compiledRule struct {
	action Action
	set    *matchSet
}

type ruleset struct {
	rules []compiledRule
	def   Action
	needs need
	// denyOnLookupError ends the evaluation with deny when a rule cannot be
	// checked because a lookup failed. Otherwise the failed selector simply
	// does not match.
	denyOnLookupError bool
}

// Decision.Rule values that are not a rule index.
const (
	ruleDefault     = -1
	ruleLookupError = -2
)

type Decision struct {
	Action Action
	// Index of the matching rule, ruleDefault or ruleLookupError.
	Rule int
}

func (d Decision) ruleName() string {
	switch d.Rule {
	case ruleDefault:
		return "default"
	case ruleLookupError:
		return "lookup_error"
	}
	return strconv.Itoa(d.Rule)
}

func (rs *ruleset) evaluate(ls *lookupState, src geoSource, obs lookupObserver) Decision {
	for i := range rs.rules {
		r := &rs.rules[i]
		matched, lookupFailed := r.set.match(ls, src, obs)
		if matched {
			return Decision{Action: r.action, Rule: i}
		}
		if lookupFailed && rs.denyOnLookupError {
			return Decision{Action: ActionDeny, Rule: ruleLookupError}
		}
	}
	return Decision{Action: rs.def, Rule: ruleDefault}
}

type groupResolver func(name string) (*spec, error)

func compileRules(rules []Rule, def string, groups groupResolver, files ipListSource) (*ruleset, error) {
	if def == "" {
		return nil, errors.New("missing default: add 'default allow' or 'default deny'")
	}
	defAction, err := ParseAction(def)
	if err != nil {
		return nil, fmt.Errorf("default: %w", err)
	}
	rs := &ruleset{def: defAction}
	for i, r := range rules {
		action, err := ParseAction(r.Action)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		if r.Selector.isEmpty() {
			return nil, fmt.Errorf("rule %d (%s): no selectors", i, r.Action)
		}
		sp, refs, err := parseSpec(r.Selector)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i, r.Action, err)
		}
		for _, g := range refs {
			gs, err := groups(g)
			if err != nil {
				return nil, fmt.Errorf("rule %d (%s): %w", i, r.Action, err)
			}
			sp.merge(gs)
		}
		set, err := compileSet(sp, files)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i, r.Action, err)
		}
		rs.rules = append(rs.rules, compiledRule{action: action, set: set})
		rs.needs |= set.needs()
	}
	return rs, nil
}

// shadowedRules returns rules that earlier rules fully cover. ip_file
// contents change at runtime, so an ip_file only counts as covered when the
// same file appears in an earlier rule.
func (rs *ruleset) shadowedRules() []int {
	var shadowed []int
	seen := &matchSet{prefixes: new(bart.Lite), asns: map[uint32]struct{}{},
		countries: map[string]struct{}{}, continents: map[string]struct{}{}}
	for i, r := range rs.rules {
		if i > 0 && covers(seen, r.set) {
			shadowed = append(shadowed, i)
		}
		if r.set.prefixes != nil {
			seen.prefixes.Union(r.set.prefixes)
		}
		for _, l := range r.set.ipFiles {
			if !slices.Contains(seen.ipFiles, l) {
				seen.ipFiles = append(seen.ipFiles, l)
			}
		}
		for k := range r.set.asns {
			seen.asns[k] = struct{}{}
		}
		for k := range r.set.countries {
			seen.countries[k] = struct{}{}
		}
		for k := range r.set.continents {
			seen.continents[k] = struct{}{}
		}
	}
	return shadowed
}

func covers(seen, m *matchSet) bool {
	if m.prefixes != nil {
		for p := range m.prefixes.All() {
			if !seen.prefixes.LookupPrefix(p) {
				return false
			}
		}
	}
	for _, l := range m.ipFiles {
		if !slices.Contains(seen.ipFiles, l) {
			return false
		}
	}
	for k := range m.asns {
		if _, ok := seen.asns[k]; !ok {
			return false
		}
	}
	for k := range m.countries {
		if _, ok := seen.countries[k]; !ok {
			return false
		}
	}
	for k := range m.continents {
		if _, ok := seen.continents[k]; !ok {
			return false
		}
	}
	return true
}
