package netacl

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Request vars set on every evaluation. Lookups are lazy, so a geo var is
// empty when no rule needed that database.
const (
	VarDecision  = "netacl_decision"
	VarRule      = "netacl_rule"    // rule index, "default" or "lookup_error"
	VarCountry   = "netacl_country" // UNK if not found
	VarContinent = "netacl_continent"
	VarASN       = "netacl_asn"
)

// The lookup cache lives in the vars map because matchers cannot attach
// values to the request context.
const lookupVarKey = "netacl.lookup_state"

// Forwarding headers are deliberately not read here: Caddy's client_ip
// already applies trusted_proxies, and reading them would bypass it.
func clientAddr(r *http.Request) netip.Addr {
	var s string
	if v, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok {
		s = v
	}
	if s == "" {
		s = r.RemoteAddr
	}
	return parseAddr(s)
}

func parseAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone("")
	}
	// "[::1]" without a port
	if host, _, err := net.SplitHostPort(s + ":0"); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a.Unmap().WithZone("")
		}
	}
	return netip.Addr{}
}

func requestLookupState(r *http.Request, addr netip.Addr) *lookupState {
	if ls, ok := caddyhttp.GetVar(r.Context(), lookupVarKey).(*lookupState); ok && ls.addr == addr {
		return ls
	}
	ls := &lookupState{addr: addr}
	caddyhttp.SetVar(r.Context(), lookupVarKey, ls)
	return ls
}

func setDecisionVars(r *http.Request, d Decision, ls *lookupState) {
	ctx := r.Context()
	caddyhttp.SetVar(ctx, VarDecision, d.Action.String())
	caddyhttp.SetVar(ctx, VarRule, d.ruleName())

	country, continent := "", ""
	if ls.countryDone && !ls.countryErr {
		country = UnknownCountry
		if ls.country.found {
			country = ls.country.country
		}
		continent = ls.country.continent
	}
	caddyhttp.SetVar(ctx, VarCountry, country)
	caddyhttp.SetVar(ctx, VarContinent, continent)

	asn := ""
	if ls.asnDone && !ls.asnErr && ls.asn.found {
		asn = strconv.FormatUint(uint64(ls.asn.asn), 10)
	}
	caddyhttp.SetVar(ctx, VarASN, asn)
}
