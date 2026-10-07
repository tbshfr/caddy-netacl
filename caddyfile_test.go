package netacl

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

var update = flag.Bool("update", false, "rewrite the adapt golden files in testdata/adapt")

const goldenSep = "----------\n"

// Run with -update to rewrite the expected JSON in testdata/adapt.
func TestCaddyfileAdapt(t *testing.T) {
	files, err := filepath.Glob("testdata/adapt/*.caddyfiletest")
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden files: %v", err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			input, want, ok := strings.Cut(string(raw), goldenSep)
			if !ok {
				t.Fatalf("missing separator %q", strings.TrimSpace(goldenSep))
			}
			got := adapt(t, input)
			if *update {
				if err := os.WriteFile(file, []byte(input+goldenSep+got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			if got != want {
				t.Errorf("adapted JSON differs (run with -update to accept)\n--- got:\n%s\n--- want:\n%s", got, want)
			}
		})
	}
}

func adapt(t *testing.T, caddyfile string) string {
	t.Helper()
	out, warnings, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(caddyfile), nil)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	for _, w := range warnings {
		t.Logf("warning: line %d: %s", w.Line, w.Message)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, out, "", "\t"); err != nil {
		t.Fatal(err)
	}
	return buf.String() + "\n"
}

func TestCaddyfileErrors(t *testing.T) {
	tests := []struct {
		name      string
		caddyfile string
		want      string
	}{
		{"unknown global option", `{
	netacl {
		db_city /x
	}
}`, `unrecognized netacl option "db_city", at Caddyfile:3`},
		{"duplicate group", `{
	netacl {
		group a 192.0.2.1
		group a 192.0.2.2
	}
}`, `duplicate group name "a", at Caddyfile:4`},
		{"group cycle", `{
	netacl {
		group a @b
		group b @a
	}
}`, `group cycle: a -> b -> a, at Caddyfile:2`},
		{"unknown group in group", `{
	netacl {
		group a @nope
	}
}`, `group "a": unknown group @nope`},
		{"empty group", `{
	netacl {
		group a
	}
}`, `group "a" has no members`},
		{"bad ip in group", `{
	netacl {
		group a 192.0.2.300
	}
}`, `invalid IP or CIDR "192.0.2.300", at Caddyfile:3`},
		{"bad asn", `{
	netacl {
		group a asn 99999999999
	}
}`, `invalid ASN "99999999999"`},
		{"bad country", `:80 {
	netacl {
		allow country Germany
		default deny
	}
}`, `invalid country code "Germany": must be two letters (ISO 3166-1 alpha-2) or UNK, at Caddyfile:3`},
		{"bad continent", `:80 {
	netacl {
		allow continent Europe
		default deny
	}
}`, `invalid continent code "Europe"`},
		{"keyword without value", `:80 {
	netacl {
		allow asn country DE
		default deny
	}
}`, `'asn' needs at least one value before 'country'`},
		{"trailing keyword", `:80 {
	netacl {
		allow country
		default deny
	}
}`, `'country' needs at least one value`},
		{"bare ip in rule", `:80 {
	netacl {
		allow 192.0.2.1
		default deny
	}
}`, `unexpected "192.0.2.1": expected a selector`},
		{"rule without selector", `:80 {
	netacl {
		allow
		default deny
	}
}`, `'allow' needs at least one selector`},
		{"missing default", `:80 {
	netacl {
		allow ip 192.0.2.1
	}
}`, `missing default`},
		{"two defaults", `:80 {
	netacl {
		default deny
		default allow
	}
}`, `default specified more than once, at Caddyfile:4`},
		{"rule after default", `:80 {
	netacl {
		default deny
		allow ip 192.0.2.1
	}
}`, `rule 'allow' after default: rules must come before default, at Caddyfile:4`},
		{"bad default", `:80 {
	netacl {
		default maybe
	}
}`, `default: invalid action "maybe"`},
		{"bad status", `:80 {
	netacl {
		status 200
		default deny
	}
}`, `invalid status "200"`},
		{"matcher without decision", `:80 {
	@m netacl {
		allow ip 192.0.2.1
		default deny
	}
	respond @m "x"
}`, `missing decision`},
		{"matcher bad decision", `:80 {
	@m netacl block {
		default deny
	}
	respond @m "x"
}`, `decision: invalid action "block"`},
		{"matcher status", `:80 {
	@m netacl deny {
		status 451
		default deny
	}
	respond @m "x"
}`, `status is not supported in the netacl matcher`},
		{"site-local group", `:80 {
	netacl {
		group a 192.0.2.1
		default deny
	}
}`, `groups are defined in the global netacl options block`},
		{"reload_interval too short", `{
	netacl {
		reload_interval 100ms
	}
}`, `invalid reload_interval "100ms": must be 0 (off) or at least 1s`},
		{"reload_interval twice", `{
	netacl {
		reload_interval 1m
		reload_interval 5m
	}
}`, `reload_interval specified more than once`},
		{"bad on_lookup_error", `:80 {
	netacl {
		on_lookup_error allow
		default deny
	}
}`, `invalid on_lookup_error "allow": must be skip or deny`},
		{"on_lookup_error twice", `:80 {
	netacl {
		on_lookup_error deny
		on_lookup_error skip
		default deny
	}
}`, `on_lookup_error specified more than once`},
		{"asn 0", `:80 {
	netacl {
		deny asn AS0
		default allow
	}
}`, `invalid ASN 0`},
		{"directive argument", `:80 {
	netacl deny
}`, `unexpected argument "deny"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(tc.caddyfile), nil)
			if err == nil {
				t.Fatalf("want error containing %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %q\nwant it to contain %q", err, tc.want)
			}
		})
	}
}
