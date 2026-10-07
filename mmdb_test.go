package netacl

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustLoadDB(t testing.TB, kind dbKind, path string) *dbHolder {
	t.Helper()
	h, err := loadDB(kind, path)
	if err != nil {
		t.Fatal(err)
	}
	holder := &dbHolder{kind: kind, path: path}
	holder.cur.Store(h)
	return holder
}

func TestCountryLookup(t *testing.T) {
	h := mustLoadDB(t, dbCountry, testDB(t, dbCountry))
	tests := map[string]countryResult{
		ipGoogle:     {found: true, country: "US", continent: "NA"},
		ipHetzner:    {found: true, country: "DE", continent: "EU"},
		ipHetzner6:   {found: true, country: "DE", continent: "EU"},
		ipCloudflare: {found: true, country: "AU", continent: "OC"},
		ipUnknown:    {},
	}
	for ip, want := range tests {
		got, err := h.lookupCountry(netip.MustParseAddr(ip))
		if err != nil || got != want {
			t.Errorf("%s: got %+v, %v; want %+v", ip, got, err, want)
		}
	}
}

func TestASNLookup(t *testing.T) {
	h := mustLoadDB(t, dbASN, testDB(t, dbASN))
	tests := map[string]asnResult{
		ipGoogle:     {found: true, asn: 15169},
		ipGoogleDE:   {found: true, asn: 15169},
		ipHetzner:    {found: true, asn: 24940},
		ipCloudflare: {found: true, asn: 13335},
		ipUnknown:    {},
	}
	for ip, want := range tests {
		got, err := h.lookupASN(netip.MustParseAddr(ip))
		if err != nil || got != want {
			t.Errorf("%s: got %+v, %v; want %+v", ip, got, err, want)
		}
	}
}

func TestLoadDBRejectsWrongType(t *testing.T) {
	_, err := loadDB(dbCountry, testDB(t, dbASN))
	if err == nil || !strings.Contains(err.Error(), "not a country or city database") || !strings.Contains(err.Error(), "db_country") {
		t.Errorf("ASN file in country slot: got %v", err)
	}
	_, err = loadDB(dbASN, testDB(t, dbCountry))
	if err == nil || !strings.Contains(err.Error(), "not an ASN database") || !strings.Contains(err.Error(), "db_asn") {
		t.Errorf("country file in ASN slot: got %v", err)
	}
}

func TestLoadDBRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadDB(dbCountry, filepath.Join(dir, "missing.mmdb")); err == nil {
		t.Error("missing file: want error")
	}

	garbage := filepath.Join(dir, "garbage.mmdb")
	writeFile(t, garbage, "this is not an mmdb file")
	if _, err := loadDB(dbCountry, garbage); err == nil {
		t.Error("garbage file: want error")
	}

	// As seen while a file is being rewritten in place.
	data, err := os.ReadFile(testDB(t, dbCountry))
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(dir, "truncated.mmdb")
	if err := os.WriteFile(truncated, data[:len(data)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDB(dbCountry, truncated); err == nil {
		t.Error("truncated file: want error")
	}
}

func TestCheckDBType(t *testing.T) {
	ok := map[string]dbKind{
		"DBIP-Country-Lite":                   dbCountry,
		"DBIP-City-Lite":                      dbCountry,
		"GeoLite2-Country":                    dbCountry,
		"GeoLite2-City":                       dbCountry,
		"GeoIP2-Country":                      dbCountry,
		"DBIP-ASN-Lite (compat=GeoLite2-ASN)": dbASN,
		"GeoLite2-ASN":                        dbASN,
	}
	for typ, kind := range ok {
		if err := checkDBType(kind, typ); err != nil {
			t.Errorf("%s in %s slot: %v", typ, kind, err)
		}
		other := dbASN
		if kind == dbASN {
			other = dbCountry
		}
		if err := checkDBType(other, typ); err == nil {
			t.Errorf("%s in %s slot: want error", typ, other)
		}
	}
}

func TestLookupWithoutDB(t *testing.T) {
	var h *dbHolder
	if _, err := h.lookupCountry(netip.MustParseAddr(ipGoogle)); err == nil {
		t.Error("want error from nil holder")
	}
}
