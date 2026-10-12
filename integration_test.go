package netacl

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestIntegration(t *testing.T) {
	country, asn := testDB(t, dbCountry), testDB(t, dbASN)

	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
		servers {
			trusted_proxies static private_ranges
		}
		netacl {
			db_country `+country+`
			db_asn     `+asn+`
			group de     country DE
			group google asn 15169
		}
	}

	http://localhost:9080 {
		handle /handler {
			netacl {
				deny  @google
				allow @de
				default deny
			}
			respond "allowed {vars.netacl_country}"
		}
		handle /status {
			netacl {
				deny ip 127.0.0.1
				status 451
				default allow
			}
			respond "allowed"
		}
		handle /matcher {
			@blocked netacl deny {
				deny country US
				default allow
			}
			respond @blocked "blocked {vars.netacl_country}" 403
			respond "ok {vars.netacl_decision}"
		}
		handle_errors {
			respond "error {err.status_code} rule={vars.netacl_rule} decision={vars.netacl_decision}" {err.status_code}
		}
	}
	`, "caddyfile")

	get := func(path, xff string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, "http://localhost:9080"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		return req
	}

	// The test client connects from 127.0.0.1, a trusted proxy here.
	tester.AssertResponse(get("/handler", ipHetzner), 200, "allowed DE")
	tester.AssertResponse(get("/handler", ipHetzner6), 200, "allowed DE")
	tester.AssertResponse(get("/handler", ipGoogleDE), 403, "error 403 rule=0 decision=deny")
	tester.AssertResponse(get("/handler", ipGoogle), 403, "error 403 rule=0 decision=deny")
	tester.AssertResponse(get("/handler", ipUnknown), 403, "error 403 rule=default decision=deny")
	// 127.0.0.1 is private, so no geo selector can match it.
	tester.AssertResponse(get("/handler", ""), 403, "error 403 rule=default decision=deny")

	tester.AssertResponse(get("/status", ""), 451, "error 451 rule=0 decision=deny")
	tester.AssertResponse(get("/status", ipHetzner), 200, "allowed")

	tester.AssertResponse(get("/matcher", ipGoogle), 403, "blocked US")
	tester.AssertResponse(get("/matcher", ipHetzner), 200, "ok allow")

	resp := tester.AssertResponseCode(get("/other", ipGoogle), 200)
	resp.Body.Close()
}

func TestIntegrationUntrustedForwardedFor(t *testing.T) {
	country := testDB(t, dbCountry)
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
		netacl {
			db_country `+country+`
		}
	}

	http://localhost:9080 {
		netacl {
			allow country DE
			default deny
		}
		respond "allowed"
	}
	`, "caddyfile")

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", ipHetzner)
	resp := tester.AssertResponseCode(req, 403)
	resp.Body.Close()
	if !strings.Contains(resp.Status, "403") {
		t.Errorf("status %s", resp.Status)
	}
}

func TestIntegrationPerHostMetrics(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
		netacl {
			per_host_metrics
		}
	}

	http://localhost:9080, http://127.0.0.1:9080 {
		netacl {
			deny ip 127.0.0.1
			default allow
		}
		respond "ok"
	}

	http://:9080 {
		netacl {
			deny ip 127.0.0.1
			default allow
		}
		respond "ok"
	}
	`, "caddyfile")

	for _, host := range []string{"localhost:9080", "127.0.0.1:9080", "attacker.test"} {
		req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp := tester.AssertResponseCode(req, 403)
		resp.Body.Close()
	}

	resp, err := tester.Client.Get("http://localhost:2999/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{
		`caddy_netacl_decisions_total{decision="deny",host="localhost"} 1`,
		`caddy_netacl_decisions_total{decision="deny",host="127.0.0.1"} 1`,
		`caddy_netacl_decisions_total{decision="deny",host="_other"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}
