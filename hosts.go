package netacl

import (
	"net"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// otherHost labels the per-host metrics of requests whose host no host
// matcher names. Clients choose the Host header freely, so labelling by it
// directly would let anyone create an unbounded number of series.
const otherHost = "_other"

// hostSet resolves a request's Host header to the counters of its host
// label: the host itself if a host matcher names it exactly, the wildcard
// pattern (such as *.example.com) that matches it, or otherHost.
type hostSet struct {
	exact map[string]*hostCounters
	// Wildcard patterns keyed by what follows "*.", so that hosts matching
	// no site cost a map lookup rather than a scan of every wildcard.
	// Clients choose those hosts, so they are the common case under attack.
	wildcards map[string]*hostCounters
	other     *hostCounters
}

// hostCounters creates the series of a host on its first request, so hosts
// whose requests never reach netacl do not show up in the metrics.
type hostCounters struct {
	host string
	once sync.Once
	c    *requestCounters
}

func (h *hostCounters) get(m *metrics) *requestCounters {
	h.once.Do(func() { h.c = m.requestCounters(h.host) })
	return h.c
}

func newHostSet(hosts []string) *hostSet {
	s := &hostSet{
		exact:     make(map[string]*hostCounters),
		wildcards: make(map[string]*hostCounters),
		other:     &hostCounters{host: otherHost},
	}
	seen := make(map[string]bool)
	for _, host := range hosts {
		host = strings.ToLower(host)
		if seen[host] {
			continue
		}
		seen[host] = true
		switch {
		case strings.Contains(host, "{"):
			// A placeholder can expand to anything.
		case strings.HasPrefix(host, "*.") && !strings.Contains(host[2:], "*"):
			s.wildcards[host[2:]] = &hostCounters{host: host}
		case strings.Contains(host, "*"):
			// No certificate covers other wildcards, such as *.*.example.com.
			// They are counted as otherHost rather than matched.
		default:
			s.exact[host] = &hostCounters{host: host}
		}
	}
	return s
}

func (s *hostSet) lookup(reqHost string) *hostCounters {
	// Normalized as caddyhttp.MatchHost does, so a request reaching a site
	// gets that site's label.
	host := reqHost
	// Browsers omit the port on 80 and 443, so hosts without a colon skip
	// SplitHostPort, which allocates its error when there is no port.
	if strings.IndexByte(host, ':') >= 0 {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else {
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		}
	}
	host = strings.ToLower(host)
	if h, ok := s.exact[host]; ok {
		return h
	}
	if _, rest, ok := strings.Cut(host, "."); ok {
		if h, ok := s.wildcards[rest]; ok {
			return h
		}
	}
	return s.other
}

// routeHosts lists the hosts of every host matcher in the http app,
// including those nested in subroutes such as handle blocks.
func routeHosts(app *caddyhttp.App) []string {
	var hosts []string
	var walk func(caddyhttp.RouteList)
	walk = func(routes caddyhttp.RouteList) {
		for _, rt := range routes {
			for _, set := range rt.MatcherSets {
				for _, m := range set {
					if hm, ok := m.(*caddyhttp.MatchHost); ok {
						hosts = append(hosts, *hm...)
					}
				}
			}
			for _, h := range rt.Handlers {
				if sr, ok := h.(*caddyhttp.Subroute); ok {
					walk(sr.Routes)
				}
			}
		}
	}
	for _, srv := range app.Servers {
		walk(srv.Routes)
		if srv.Errors != nil {
			walk(srv.Errors.Routes)
		}
	}
	return hosts
}
