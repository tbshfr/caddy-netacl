package netacl

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Policy struct {
	// Evaluated top to bottom; the first match decides.
	Rules []Rule `json:"rules,omitempty"`
	// allow or deny, used when no rule matches. Required.
	Default string `json:"default"`
	// What a failed country or ASN lookup does. "skip" (the default): the
	// selectors that needed it do not match and evaluation continues, so a
	// deny rule fails open. "deny": the request is denied as soon as a rule
	// cannot be checked, so the policy fails closed.
	OnLookupError string `json:"on_lookup_error,omitempty"`
}

const (
	lookupErrorSkip = "skip"
	lookupErrorDeny = "deny"
)

func parseOnLookupError(s string) (bool, error) {
	switch s {
	case "", lookupErrorSkip:
		return false, nil
	case lookupErrorDeny:
		return true, nil
	}
	return false, fmt.Errorf("invalid on_lookup_error %q: must be skip or deny", s)
}

type engine struct {
	rs      *ruleset
	src     geoSource
	metrics *metrics
	logger  *zap.Logger
	errLog  *logThrottle
}

// logThrottle lets one log entry through per interval, so a database whose
// lookups keep failing cannot flood the logs with one entry per request.
type logThrottle struct {
	every      time.Duration
	next       atomic.Int64 // unix nanoseconds
	suppressed atomic.Int64
}

// allow reports whether to log now, and how many entries were suppressed
// since the last one.
func (t *logThrottle) allow(now time.Time) (bool, int64) {
	next := t.next.Load()
	if now.UnixNano() < next || !t.next.CompareAndSwap(next, now.Add(t.every).UnixNano()) {
		t.suppressed.Add(1)
		return false, 0
	}
	return true, t.suppressed.Swap(0)
}

func (p *Policy) provision(ctx caddy.Context) (*engine, error) {
	appIface, err := ctx.App("netacl")
	if err != nil {
		return nil, fmt.Errorf("getting netacl app: %w", err)
	}
	return p.compile(appIface.(*App), ctx.Logger())
}

func (p *Policy) compile(app *App, logger *zap.Logger) (*engine, error) {
	denyOnErr, err := parseOnLookupError(p.OnLookupError)
	if err != nil {
		return nil, err
	}
	rs, err := compileRules(p.Rules, p.Default, app.groups.lookup, app.ipList)
	if err != nil {
		return nil, err
	}
	rs.denyOnLookupError = denyOnErr
	if rs.needs&needCountry != 0 {
		if _, err := app.database(dbCountry); err != nil {
			return nil, err
		}
	}
	if rs.needs&needASN != 0 {
		if _, err := app.database(dbASN); err != nil {
			return nil, err
		}
	}
	for _, i := range rs.shadowedRules() {
		logger.Warn("rule can never match: earlier rules already cover all of its selectors",
			zap.Int("rule", i), zap.String("rule_summary", describeRule(p.Rules[i])))
	}
	return &engine{rs: rs, src: app.geoSource(), metrics: app.metrics, logger: logger, errLog: &app.lookupErrLog}, nil
}

func (e *engine) evaluate(r *http.Request) Decision {
	addr := clientAddr(r)
	ls := requestLookupState(r, addr)
	d := e.rs.evaluate(ls, e.src, e.observeLookup)
	setDecisionVars(r, d, ls)
	e.metrics.decisionCounters[d.Action].Inc()
	if ce := e.logger.Check(zapcore.DebugLevel, "netacl decision"); ce != nil {
		client := addr.String()
		if !addr.IsValid() {
			client = "none (treated as unknown address)"
		}
		ce.Write(zap.String("client_ip", client),
			zap.String("decision", d.Action.String()),
			zap.String("rule", d.ruleName()))
	}
	return d
}

func (e *engine) observeLookup(db string, addr netip.Addr, result string, err error) {
	e.metrics.lookupCounters[[2]string{db, result}].Inc()
	if err != nil {
		if ok, suppressed := e.errLog.allow(time.Now()); ok {
			e.logger.Error("database lookup failed; further failures within a minute are only counted in caddy_netacl_lookups_total",
				zap.String("db", db), zap.Error(err), zap.Int64("suppressed_since_last", suppressed))
		}
		return
	}
	if ce := e.logger.Check(zapcore.DebugLevel, "database lookup"); ce != nil {
		ce.Write(zap.String("db", db), zap.String("client_ip", addr.String()), zap.String("result", result))
	}
}

func describeRule(r Rule) string {
	parts := []string{r.Action}
	for _, g := range r.Groups {
		parts = append(parts, "@"+g)
	}
	if len(r.IPs) > 0 {
		parts = append(parts, "ip "+strings.Join(r.IPs, " "))
	}
	for _, f := range r.IPFiles {
		parts = append(parts, "ip_file "+f)
	}
	if r.PrivateRanges {
		parts = append(parts, "private_ranges")
	}
	if len(r.ASNs) > 0 {
		s := make([]string, len(r.ASNs))
		for i, a := range r.ASNs {
			s[i] = fmt.Sprint(a)
		}
		parts = append(parts, "asn "+strings.Join(s, " "))
	}
	if len(r.Countries) > 0 {
		parts = append(parts, "country "+strings.Join(r.Countries, " "))
	}
	if len(r.Continents) > 0 {
		parts = append(parts, "continent "+strings.Join(r.Continents, " "))
	}
	return strings.Join(parts, " ")
}
