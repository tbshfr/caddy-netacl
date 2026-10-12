package netacl

import (
	"errors"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	decisions *prometheus.CounterVec
	lookups   *prometheus.CounterVec
	reloads   *prometheus.CounterVec
	downloads *prometheus.CounterVec
	buildTime *prometheus.GaugeVec

	// Adds a host label to decisions and lookups.
	perHost bool
	// Lists the hosts that get their own label. Called once, on the first
	// request, because the http app's host matchers are only provisioned
	// after this app.
	listHosts func() []string
	hostsOnce sync.Once
	hosts     *hostSet

	// Per-request counters, resolved once (per host with perHost) so the
	// request path does not hash label values.
	all *requestCounters
}

type requestCounters struct {
	decisions map[Action]prometheus.Counter
	lookups   map[[2]string]prometheus.Counter
}

func newMetrics(perHost bool) *metrics {
	const ns, sub = "caddy", "netacl"
	decisionLabels, lookupLabels := []string{"decision"}, []string{"db", "result"}
	if perHost {
		decisionLabels = append(decisionLabels, "host")
		lookupLabels = append(lookupLabels, "host")
	}
	return &metrics{
		perHost: perHost,
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "decisions_total",
			Help: "Number of netacl evaluations by decision.",
		}, decisionLabels),
		lookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "lookups_total",
			Help: "Number of database lookups by database and result (hit, miss, error).",
		}, lookupLabels),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "db_reloads_total",
			Help: "Number of database and ip_file reload attempts by database and result (success, error).",
		}, []string{"db", "result"}),
		downloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "db_downloads_total",
			Help: "Number of auto_update downloads by database and result (success, error).",
		}, []string{"db", "result"}),
		buildTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns, Subsystem: sub, Name: "db_build_epoch_seconds",
			Help: "Build time of the loaded database, from its metadata, in seconds since the Unix epoch.",
		}, []string{"db"}),
	}
}

// Already registered collectors are reused, so app instances sharing a
// registry report into the same series instead of failing.
func (m *metrics) register(reg prometheus.Registerer) error {
	defer m.resolve()
	if reg == nil {
		return nil
	}
	var err error
	m.decisions, err = registerOrReuse(reg, m.decisions)
	if err != nil {
		return err
	}
	m.lookups, err = registerOrReuse(reg, m.lookups)
	if err != nil {
		return err
	}
	m.reloads, err = registerOrReuse(reg, m.reloads)
	if err != nil {
		return err
	}
	m.downloads, err = registerOrReuse(reg, m.downloads)
	if err != nil {
		return err
	}
	m.buildTime, err = registerOrReuse(reg, m.buildTime)
	return err
}

func (m *metrics) resolve() {
	// Per-host series are created on each host's first request instead.
	if !m.perHost {
		m.all = m.requestCounters()
	}
	// Export reload and download series at 0 up front: a series that first
	// appears at 1 is invisible to increase(), hiding the first failure.
	for _, result := range []string{"success", "error"} {
		for _, db := range []string{dbCountry.String(), dbASN.String()} {
			m.reloads.WithLabelValues(db, result)
			m.downloads.WithLabelValues(db, result)
		}
		m.reloads.WithLabelValues("ip_file", result)
	}
}

// requestCounters resolves the per-request counters, with host as the last
// label value if given. All of them are created together, so the first deny
// of a host is visible to increase() even if its first request was allowed.
func (m *metrics) requestCounters(host ...string) *requestCounters {
	c := &requestCounters{
		decisions: make(map[Action]prometheus.Counter),
		lookups:   make(map[[2]string]prometheus.Counter),
	}
	for _, a := range []Action{ActionAllow, ActionDeny} {
		c.decisions[a] = m.decisions.WithLabelValues(append([]string{a.String()}, host...)...)
	}
	for _, db := range []string{dbCountry.String(), dbASN.String()} {
		for _, result := range []string{"hit", "miss", "error"} {
			c.lookups[[2]string{db, result}] = m.lookups.WithLabelValues(append([]string{db, result}, host...)...)
		}
	}
	return c
}

func (m *metrics) forRequest(r *http.Request) *requestCounters {
	if !m.perHost {
		return m.all
	}
	m.hostsOnce.Do(func() {
		var hosts []string
		if m.listHosts != nil {
			hosts = m.listHosts()
		}
		m.hosts = newHostSet(hosts)
	})
	return m.hosts.lookup(r.Host).get(m)
}

func registerOrReuse[C prometheus.Collector](reg prometheus.Registerer, c C) (C, error) {
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(C); ok {
				return existing, nil
			}
		}
		return c, err
	}
	return c, nil
}
