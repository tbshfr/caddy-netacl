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
func clientAddr(vars map[string]any, r *http.Request) netip.Addr {
	s, _ := vars[caddyhttp.ClientIPVarKey].(string)
	if s == "" {
		s = r.RemoteAddr
	}
	return parseAddr(s)
}

func parseAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	// client_ip is a bare address, so that is tried first.
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone("")
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	// "[::1]" without a port
	if host, _, err := net.SplitHostPort(s + ":0"); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a.Unmap().WithZone("")
		}
	}
	return netip.Addr{}
}

// requestVars returns the request's vars map, or nil outside Caddy's HTTP
// server. It is fetched once per evaluation because each lookup walks the
// request's context chain.
func requestVars(r *http.Request) map[string]any {
	vars, _ := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any)
	return vars
}

func requestLookupState(vars map[string]any, addr netip.Addr) *lookupState {
	if ls, ok := vars[lookupVarKey].(*lookupState); ok && ls.addr == addr {
		return ls
	}
	ls := &lookupState{addr: addr}
	if vars != nil {
		vars[lookupVarKey] = ls
	}
	return ls
}

// Var values are boxed once up front: storing a string in the vars map
// otherwise allocates on every request.
var (
	actionVars           = [...]any{ActionAllow: ActionAllow.String(), ActionDeny: ActionDeny.String()}
	ruleDefaultVar   any = Decision{Rule: ruleDefault}.ruleName()
	ruleLookupErrVar any = Decision{Rule: ruleLookupError}.ruleName()
	// Two-letter country and continent codes, see codeVar.
	codeVars = func() (v [26 * 26]any) {
		for i := range v {
			v[i] = string([]byte{'A' + byte(i/26), 'A' + byte(i%26)})
		}
		return v
	}()
)

func codeVar(s string) any {
	if len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z' {
		return codeVars[int(s[0]-'A')*26+int(s[1]-'A')]
	}
	return s
}

func setDecisionVars(vars map[string]any, rs *ruleset, d Decision, ls *lookupState) {
	if vars == nil {
		return
	}
	vars[VarDecision] = actionVars[d.Action]
	switch d.Rule {
	case ruleDefault:
		vars[VarRule] = ruleDefaultVar
	case ruleLookupError:
		vars[VarRule] = ruleLookupErrVar
	default:
		vars[VarRule] = rs.rules[d.Rule].varValue
	}

	var country, continent any = "", ""
	if ls.countryDone && !ls.countryErr {
		country = UnknownCountry
		if ls.country.found {
			country = codeVar(ls.country.country)
		}
		continent = codeVar(ls.country.continent)
	}
	vars[VarCountry] = country
	vars[VarContinent] = continent

	var asn any = ""
	if ls.asnDone && !ls.asnErr && ls.asn.found {
		asn = ls.asn.varValue
		if asn == nil {
			asn = strconv.FormatUint(uint64(ls.asn.asn), 10)
		}
	}
	vars[VarASN] = asn
}
