package netacl

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsExportedAtZero(t *testing.T) {
	m := newMetrics()
	if err := m.register(prometheus.NewRegistry()); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		c    prometheus.Collector
		want int
	}{
		"decisions": {m.decisions, 2},
		"lookups":   {m.lookups, 6},
		"reloads":   {m.reloads, 6},
		"downloads": {m.downloads, 4},
		"buildTime": {m.buildTime, 0}, // a 0 build time would read as a 56-year-old database
	} {
		if got := testutil.CollectAndCount(tc.c); got != tc.want {
			t.Errorf("%s: %d series before any event, want %d", name, got, tc.want)
		}
	}
}
