package netacl

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	decisions *prometheus.CounterVec
	lookups   *prometheus.CounterVec
	reloads   *prometheus.CounterVec
	downloads *prometheus.CounterVec
	buildTime *prometheus.GaugeVec

	// Per-request counters, resolved once so the request path does not
	// hash label values.
	decisionCounters map[Action]prometheus.Counter
	lookupCounters   map[[2]string]prometheus.Counter
}

func newMetrics() *metrics {
	const ns, sub = "caddy", "netacl"
	return &metrics{
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "decisions_total",
			Help: "Number of netacl evaluations by decision.",
		}, []string{"decision"}),
		lookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "lookups_total",
			Help: "Number of database lookups by database and result (hit, miss, error).",
		}, []string{"db", "result"}),
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
	m.decisionCounters = map[Action]prometheus.Counter{
		ActionAllow: m.decisions.WithLabelValues(ActionAllow.String()),
		ActionDeny:  m.decisions.WithLabelValues(ActionDeny.String()),
	}
	m.lookupCounters = make(map[[2]string]prometheus.Counter)
	for _, db := range []string{dbCountry.String(), dbASN.String()} {
		for _, result := range []string{"hit", "miss", "error"} {
			m.lookupCounters[[2]string{db, result}] = m.lookups.WithLabelValues(db, result)
		}
	}
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
