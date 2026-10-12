package netacl

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsExportedAtZero(t *testing.T) {
	for _, perHost := range []bool{false, true} {
		t.Run(fmt.Sprintf("perHost=%v", perHost), func(t *testing.T) {
			m := newMetrics(perHost)
			if err := m.register(prometheus.NewRegistry()); err != nil {
				t.Fatal(err)
			}
			// Per-host series appear on each host's first request.
			decisions, lookups := 2, 6
			if perHost {
				decisions, lookups = 0, 0
			}
			for name, tc := range map[string]struct {
				c    prometheus.Collector
				want int
			}{
				"decisions": {m.decisions, decisions},
				"lookups":   {m.lookups, lookups},
				"reloads":   {m.reloads, 6},
				"downloads": {m.downloads, 4},
				"buildTime": {m.buildTime, 0}, // a 0 build time would read as a 56-year-old database
			} {
				if got := testutil.CollectAndCount(tc.c); got != tc.want {
					t.Errorf("%s: %d series before any event, want %d", name, got, tc.want)
				}
			}
		})
	}
}
