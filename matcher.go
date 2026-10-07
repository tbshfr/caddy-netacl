package netacl

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(new(Matcher))
}

// Matcher matches when the policy's decision equals Decision. The decision
// is required so a matcher's polarity is never implicit.
type Matcher struct {
	// allow or deny. Required.
	Decision string `json:"decision"`
	Policy

	want   Action
	engine *engine
}

func (*Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.netacl",
		New: func() caddy.Module { return new(Matcher) },
	}
}

func (m *Matcher) Provision(ctx caddy.Context) error {
	if m.Decision == "" {
		return fmt.Errorf("netacl matcher: missing decision: use 'netacl allow { ... }' or 'netacl deny { ... }'")
	}
	want, err := ParseAction(m.Decision)
	if err != nil {
		return fmt.Errorf("netacl matcher: decision: %w", err)
	}
	m.want = want
	e, err := m.Policy.provision(ctx)
	if err != nil {
		return err
	}
	m.engine = e
	return nil
}

func (m *Matcher) MatchWithError(r *http.Request) (bool, error) {
	return m.engine.evaluate(r).Action == m.want, nil
}

func (m *Matcher) Match(r *http.Request) bool {
	ok, _ := m.MatchWithError(r)
	return ok
}

var (
	_ caddy.Provisioner                 = (*Matcher)(nil)
	_ caddyhttp.RequestMatcherWithError = (*Matcher)(nil)
	_ caddyhttp.RequestMatcher          = (*Matcher)(nil)
)
