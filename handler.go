package netacl

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(new(Handler))
}

// Handler denies with a Caddy HTTP error rather than writing a response, so
// handle_errors can style it.
type Handler struct {
	Policy
	// Default: 403.
	StatusCode int `json:"status_code,omitempty"`

	engine *engine
}

func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.netacl",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	if h.StatusCode == 0 {
		h.StatusCode = http.StatusForbidden
	}
	if h.StatusCode < 400 || h.StatusCode > 599 {
		return fmt.Errorf("status_code %d: must be an HTTP error status (400-599)", h.StatusCode)
	}
	e, err := h.Policy.provision(ctx)
	if err != nil {
		return err
	}
	h.engine = e
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d := h.engine.evaluate(r)
	if d.Action == ActionDeny {
		var reason string
		switch d.Rule {
		case ruleDefault:
			reason = "default"
		case ruleLookupError:
			reason = "a failed database lookup (on_lookup_error deny)"
		default:
			reason = "rule " + d.ruleName()
		}
		return caddyhttp.Error(h.StatusCode, fmt.Errorf("netacl: request denied by %s", reason))
	}
	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
