package netacl

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The databases are not committed because they are 18 MB and change monthly.
// Tests download them on first use and reuse them; delete
// testdata/dbip/*.mmdb to refresh.
const testDBDir = "testdata/dbip"

// Addresses with long-standing, stable assignments in DB-IP Lite.
const (
	ipGoogle     = "8.8.8.8"           // US, NA, AS15169
	ipGoogleDE   = "2a00:1450:4001::1" // DE, EU, AS15169
	ipHetzner    = "88.198.1.1"        // DE, EU, AS24940
	ipHetzner6   = "2a01:4f8::1"       // DE, EU, AS24940
	ipCloudflare = "1.1.1.1"           // AU, OC, AS13335
	ipUnknown    = "203.0.113.9"       // TEST-NET-3: in neither database, but not private
)

var (
	testDBOnce sync.Once
	testDBErr  error
)

func testDB(t testing.TB, kind dbKind) string {
	t.Helper()
	testDBOnce.Do(func() { testDBErr = downloadTestDBs() })
	if testDBErr != nil {
		t.Fatalf("downloading DB-IP Lite databases into %s: %v", testDBDir, testDBErr)
	}
	path, err := filepath.Abs(filepath.Join(testDBDir, dbipFileName(kind)))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func downloadTestDBs() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := &http.Client{}
	for _, kind := range []dbKind{dbCountry, dbASN} {
		dst := filepath.Join(testDBDir, dbipFileName(kind))
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		if _, err := fetchLatestDBIP(ctx, client, dbipBaseURL, kind, time.Now(), dst); err != nil {
			return fmt.Errorf("%s: %w", kind, err)
		}
	}
	return nil
}
