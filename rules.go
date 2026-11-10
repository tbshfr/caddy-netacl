package netacl

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

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
	IPFiles []string `json:"ip_files,omitempty"`
	// Published lists such as github/hooks, fetched from the app's
	// lists_url and kept current.
	Lists         []string `json:"lists,omitempty"`
	PrivateRanges bool     `json:"private_ranges,omitempty"`
	ASNs          []uint32 `json:"asns,omitempty"`
	// ISO 3166-1 alpha-2 codes, or UNK.
	Countries []string `json:"countries,omitempty"`
	// AF, AN, AS, EU, NA, OC or SA.
	Continents []string `json:"continents,omitempty"`
}

func (s Selector) isEmpty() bool {
	return len(s.Groups) == 0 && len(s.IPs) == 0 && len(s.IPFiles) == 0 && len(s.Lists) == 0 &&
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
	lists      []string
	asns       []uint32
	countries  []string
	continents []string

	tableOnce sync.Once
	table     *bart.Lite
}

func newPrefixTable(prefixes []netip.Prefix) *bart.Lite {
	if len(prefixes) == 0 {
		return nil
	}
	t := new(bart.Lite)
	for _, p := range prefixes {
		t.Insert(p)
	}
	return t
}

// Shared by every rule that is a single group reference, so it must not be
// modified.
func (s *spec) prefixTable() *bart.Lite {
	s.tableOnce.Do(func() { s.table = newPrefixTable(s.prefixes) })
	return s.table
}

func (s *spec) merge(o *spec) {
	s.prefixes = append(s.prefixes, o.prefixes...)
	s.ipFiles = append(s.ipFiles, o.ipFiles...)
	s.lists = append(s.lists, o.lists...)
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
	for _, l := range sel.Lists {
		if err := validateListName(l); err != nil {
			return nil, nil, err
		}
		sp.lists = append(sp.lists, l)
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
	prefixes *bart.Lite
	// Both ip_file and list selectors.
	ipFiles    []*ipList
	asns       map[uint32]struct{}
	countries  codeSet
	continents codeSet
}

// A bitmap rather than a map, because every country rule tests it on every
// request.
type codeSet struct {
	bits     [(26*26 + 63) / 64]uint64
	unknown  bool
	nonEmpty bool
}

func codeIndex(s string) (int, bool) {
	if len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z' {
		return int(s[0]-'A')*26 + int(s[1]-'A'), true
	}
	return 0, false
}

// add expects a code that ParseCountry or ParseContinent returned.
func (c *codeSet) add(code string) {
	if i, ok := codeIndex(code); ok {
		c.bits[i/64] |= 1 << (i % 64)
	} else {
		c.unknown = true
	}
	c.nonEmpty = true
}

func (c *codeSet) has(code string) bool {
	i, ok := codeIndex(code)
	return ok && c.bits[i/64]&(1<<(i%64)) != 0
}

func (c *codeSet) addAll(o *codeSet) {
	for i, b := range o.bits {
		c.bits[i] |= b
	}
	c.unknown = c.unknown || o.unknown
	c.nonEmpty = c.nonEmpty || o.nonEmpty
}

func (c *codeSet) covers(o *codeSet) bool {
	for i, b := range o.bits {
		if b&^c.bits[i] != 0 {
			return false
		}
	}
	return c.unknown || !o.unknown
}

type ipListSource func(path string) (*ipList, error)

// shared, if set, is a table that already holds exactly sp's prefixes.
func compileSet(sp *spec, shared *bart.Lite, files, lists ipListSource) (*matchSet, error) {
	m := &matchSet{prefixes: shared}
	if m.prefixes == nil {
		m.prefixes = newPrefixTable(sp.prefixes)
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
	for _, name := range sp.lists {
		l, err := lists(name)
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
	for _, c := range sp.countries {
		m.countries.add(c)
	}
	for _, c := range sp.continents {
		m.continents.add(c)
	}
	return m, nil
}

func (m *matchSet) needs() need {
	var n need
	if m.countries.nonEmpty || m.continents.nonEmpty {
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
	// The netacl_asn var value, formatted and boxed once per cached record.
	// Nil when the source did not set it.
	varValue any
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

type lookupResult uint8

const (
	lookupHit lookupResult = iota
	lookupMiss
	lookupError
)

func (r lookupResult) String() string {
	switch r {
	case lookupHit:
		return "hit"
	case lookupMiss:
		return "miss"
	}
	return "error"
}

func classifyLookup(found bool, err error) lookupResult {
	switch {
	case err != nil:
		return lookupError
	case !found:
		return lookupMiss
	}
	return lookupHit
}

type lookupObserver func(db dbKind, addr netip.Addr, result lookupResult, err error)

func (ls *lookupState) ensureCountry(src geoSource, obs lookupObserver) {
	if ls.countryDone {
		return
	}
	ls.countryDone = true
	r, err := src.lookupCountry(ls.addr)
	ls.countryErr = err != nil
	ls.country = r
	if obs != nil {
		obs(dbCountry, ls.addr, classifyLookup(r.found, err), err)
	}
}

func (ls *lookupState) ensureASN(src geoSource, obs lookupObserver) {
	if ls.asnDone {
		return
	}
	ls.asnDone = true
	r, err := src.lookupASN(ls.addr)
	ls.asnErr = err != nil
	ls.asn = r
	if obs != nil {
		obs(dbASN, ls.addr, classifyLookup(r.found, err), err)
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
	if m.countries.nonEmpty || m.continents.nonEmpty {
		ls.ensureCountry(src, obs)
		if ls.countryErr {
			lookupFailed = true
		} else {
			c := &ls.country
			if c.found {
				if m.countries.has(c.country) {
					return true, false
				}
			} else if m.countries.unknown {
				return true, false
			}
			if m.continents.has(c.continent) {
				return true, false
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
	// The netacl_rule var value, boxed once instead of on every request.
	varValue any
}

type ruleset struct {
	rules []compiledRule
	def   Action
	needs need
	// denyOnLookupError ends the evaluation with deny when a rule cannot be
	// checked because a lookup failed or the request has no client address.
	// Otherwise the failed selector simply does not match.
	denyOnLookupError bool
}

// Decision.Rule values that are not a rule index.
const (
	ruleDefault     = -1
	ruleLookupError = -2
	ruleNoClientIP  = -3
)

type Decision struct {
	Action Action
	// Index of the matching rule, ruleDefault, ruleLookupError or
	// ruleNoClientIP.
	Rule int
}

func (d Decision) ruleName() string {
	switch d.Rule {
	case ruleDefault:
		return "default"
	case ruleLookupError:
		return "lookup_error"
	case ruleNoClientIP:
		return "no_client_ip"
	}
	return strconv.Itoa(d.Rule)
}

func (rs *ruleset) evaluate(ls *lookupState, src geoSource, obs lookupObserver) Decision {
	// No rule can be checked without a client address, so a fail-closed
	// policy must not reach the default.
	if rs.denyOnLookupError && !ls.addr.IsValid() {
		return Decision{Action: ActionDeny, Rule: ruleNoClientIP}
	}
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

func compileRules(rules []Rule, def string, groups groupResolver, files, lists ipListSource) (*ruleset, error) {
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
		ownPrefixes := len(sp.prefixes)
		var shared *bart.Lite
		for _, g := range refs {
			gs, err := groups(g)
			if err != nil {
				return nil, fmt.Errorf("rule %d (%s): %w", i, r.Action, err)
			}
			sp.merge(gs)
			if ownPrefixes == 0 && len(refs) == 1 {
				shared = gs.prefixTable()
			}
		}
		set, err := compileSet(sp, shared, files, lists)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i, r.Action, err)
		}
		rs.rules = append(rs.rules, compiledRule{action: action, set: set, varValue: strconv.Itoa(i)})
		rs.needs |= set.needs()
	}
	return rs, nil
}

// shadowedRules returns rules that earlier rules fully cover. ip_file and list
// contents change at runtime, so they only count as covered when the same
// file or list appears in an earlier rule.
func (rs *ruleset) shadowedRules() []int {
	var shadowed []int
	seen := &matchSet{prefixes: new(bart.Lite), asns: map[uint32]struct{}{}}
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
		seen.countries.addAll(&r.set.countries)
		seen.continents.addAll(&r.set.continents)
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
	return seen.countries.covers(&m.countries) && seen.continents.covers(&m.continents)
}
