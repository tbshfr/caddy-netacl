package netacl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("netacl", parseGlobalOption)
	httpcaddyfile.RegisterHandlerDirective("netacl", parseHandlerDirective)
	// Run before every standard directive, so that neither they nor plugins
	// ordered relative to them (e.g. static_redirects before header) can
	// answer a request before the policy is checked.
	httpcaddyfile.RegisterDirectiveOrder("netacl", httpcaddyfile.Before, "tracing")
}

func parseGlobalOption(d *caddyfile.Dispenser, existing any) (any, error) {
	if existing != nil {
		return nil, d.Err("netacl global option specified more than once")
	}
	app := new(App)
	d.Next()
	if d.NextArg() {
		return nil, d.ArgErr()
	}
	file, line := d.File(), d.Line()
	for d.NextBlock(0) {
		switch d.Val() {
		case "db_country", "db_asn":
			opt := d.Val()
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			path := d.Val()
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			if opt == "db_country" {
				if app.DBCountry != "" {
					return nil, d.Errf("%s specified more than once", opt)
				}
				app.DBCountry = path
			} else {
				if app.DBASN != "" {
					return nil, d.Errf("%s specified more than once", opt)
				}
				app.DBASN = path
			}

		case "auto_update":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			app.AutoUpdate = true

		case "reload_interval":
			if app.ReloadInterval != 0 {
				return nil, d.Err("reload_interval specified more than once")
			}
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("invalid reload_interval %q: %v", d.Val(), err)
			}
			if dur != 0 && dur < minReloadInterval {
				return nil, d.Errf("invalid reload_interval %q: must be 0 (off) or at least %s", d.Val(), minReloadInterval)
			}
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			app.ReloadInterval = caddy.Duration(dur)

		case "group":
			if !d.NextArg() {
				return nil, d.Err("group needs a name")
			}
			name := strings.TrimPrefix(d.Val(), "@")
			if err := validateGroupName(name); err != nil {
				return nil, d.Err(err.Error())
			}
			if _, dup := app.Groups[name]; dup {
				return nil, d.Errf("duplicate group name %q", name)
			}
			var sel Selector
			p := selectorParser{sel: &sel, bareIPs: true}
			for d.NextArg() {
				if err := p.feed(d); err != nil {
					return nil, err
				}
			}
			if err := p.finish(d); err != nil {
				return nil, err
			}
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				p.newLine()
				if err := p.feed(d); err != nil {
					return nil, err
				}
				for d.NextArg() {
					if err := p.feed(d); err != nil {
						return nil, err
					}
				}
				if err := p.finish(d); err != nil {
					return nil, err
				}
			}
			if sel.isEmpty() {
				return nil, d.Errf("group %q has no members", name)
			}
			if app.Groups == nil {
				app.Groups = make(map[string]Selector)
			}
			app.Groups[name] = sel

		default:
			return nil, d.Errf("unrecognized netacl option %q", d.Val())
		}
	}

	// Also checked at provision time, but checking here lets caddy adapt
	// report unknown references and cycles.
	if _, err := resolveGroups(app.Groups); err != nil {
		return nil, fmt.Errorf("%w, at %s:%d", err, file, line)
	}

	return httpcaddyfile.App{
		Name:  "netacl",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

func parseHandlerDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	hd := new(Handler)
	if err := hd.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return hd, nil
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.Errf("unexpected argument %q: netacl takes a block of rules", d.Val())
	}
	status, err := parsePolicyBlock(d, &h.Policy, true)
	if err != nil {
		return err
	}
	h.StatusCode = status
	return nil
}

func (m *Matcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	parsed := false
	for d.Next() {
		if parsed {
			return d.Err("netacl matcher may only be used once per named matcher")
		}
		parsed = true
		if !d.NextArg() {
			return d.Err("netacl matcher: missing decision: use 'netacl allow { ... }' or 'netacl deny { ... }'")
		}
		if _, err := ParseAction(d.Val()); err != nil {
			return d.Errf("netacl matcher: decision: %v", err)
		}
		m.Decision = d.Val()
		if d.NextArg() {
			return d.Errf("unexpected argument %q after netacl matcher decision", d.Val())
		}
		if _, err := parsePolicyBlock(d, &m.Policy, false); err != nil {
			return err
		}
	}
	return nil
}

func parsePolicyBlock(d *caddyfile.Dispenser, p *Policy, allowStatus bool) (int, error) {
	status := 0
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch kw := d.Val(); kw {
		case "allow", "deny":
			if p.Default != "" {
				return 0, d.Errf("rule '%s' after default: rules must come before default", kw)
			}
			r := Rule{Action: kw}
			sp := selectorParser{sel: &r.Selector}
			for d.NextArg() {
				if err := sp.feed(d); err != nil {
					return 0, err
				}
			}
			if err := sp.finish(d); err != nil {
				return 0, err
			}
			if r.Selector.isEmpty() {
				return 0, d.Errf("'%s' needs at least one selector", kw)
			}
			p.Rules = append(p.Rules, r)

		case "default":
			if p.Default != "" {
				return 0, d.Err("default specified more than once")
			}
			if !d.NextArg() {
				return 0, d.Err("default needs allow or deny")
			}
			if _, err := ParseAction(d.Val()); err != nil {
				return 0, d.Errf("default: %v", err)
			}
			p.Default = d.Val()
			if d.NextArg() {
				return 0, d.ArgErr()
			}

		case "on_lookup_error":
			if p.OnLookupError != "" {
				return 0, d.Err("on_lookup_error specified more than once")
			}
			if !d.NextArg() {
				return 0, d.ArgErr()
			}
			if _, err := parseOnLookupError(d.Val()); err != nil {
				return 0, d.Err(err.Error())
			}
			p.OnLookupError = d.Val()
			if d.NextArg() {
				return 0, d.ArgErr()
			}

		case "status":
			if !allowStatus {
				return 0, d.Err("status is not supported in the netacl matcher; set it on the handler that responds")
			}
			if status != 0 {
				return 0, d.Err("status specified more than once")
			}
			if !d.NextArg() {
				return 0, d.ArgErr()
			}
			code, err := strconv.Atoi(d.Val())
			if err != nil || code < 400 || code > 599 {
				return 0, d.Errf("invalid status %q: must be an HTTP error status (400-599)", d.Val())
			}
			status = code
			if d.NextArg() {
				return 0, d.ArgErr()
			}

		case "group":
			return 0, d.Err("groups are defined in the global netacl options block, not in sites")

		default:
			return 0, d.Errf("unrecognized netacl subdirective %q", kw)
		}
	}
	if p.Default == "" {
		return 0, d.Err("missing default: add 'default allow' or 'default deny' after the rules")
	}
	return status, nil
}

const selectorKeywords = "ip, ip_file, private_ranges, asn, country, continent"

// selectorParser is fed one token at a time, so errors point at the
// offending token.
type selectorParser struct {
	sel     *Selector
	bareIPs bool // groups accept IPs without the ip keyword
	mode    string
	pending string // keyword still waiting for its first value
}

func (p *selectorParser) newLine() {
	p.mode = ""
	p.pending = ""
}

func (p *selectorParser) feed(d *caddyfile.Dispenser) error {
	tok := d.Val()
	if strings.HasPrefix(tok, "@") {
		name := tok[1:]
		if err := validateGroupName(name); err != nil {
			return d.Err(err.Error())
		}
		p.sel.Groups = append(p.sel.Groups, name)
		return nil
	}
	switch tok {
	case "ip", "ip_file", "asn", "country", "continent", "private_ranges":
		if p.pending != "" {
			return d.Errf("'%s' needs at least one value before '%s'", p.pending, tok)
		}
		if tok == "private_ranges" {
			p.sel.PrivateRanges = true
			p.mode = ""
			return nil
		}
		p.mode, p.pending = tok, tok
		return nil
	}

	mode := p.mode
	if mode == "" && p.bareIPs {
		mode = "ip"
	}
	switch mode {
	case "":
		return d.Errf("unexpected %q: expected a selector (%s) or @group", tok, selectorKeywords)
	case "ip":
		if _, err := ParsePrefix(tok); err != nil {
			return d.Err(err.Error())
		}
		p.sel.IPs = append(p.sel.IPs, tok)
	case "ip_file":
		p.sel.IPFiles = append(p.sel.IPFiles, tok)
	case "asn":
		n, err := ParseASN(tok)
		if err != nil {
			return d.Err(err.Error())
		}
		p.sel.ASNs = append(p.sel.ASNs, n)
	case "country":
		c, err := ParseCountry(tok)
		if err != nil {
			return d.Err(err.Error())
		}
		p.sel.Countries = append(p.sel.Countries, c)
	case "continent":
		c, err := ParseContinent(tok)
		if err != nil {
			return d.Err(err.Error())
		}
		p.sel.Continents = append(p.sel.Continents, c)
	}
	p.pending = ""
	return nil
}

func (p *selectorParser) finish(d *caddyfile.Dispenser) error {
	if p.pending != "" {
		return d.Errf("'%s' needs at least one value", p.pending)
	}
	return nil
}

var (
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Matcher)(nil)
)
