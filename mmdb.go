package netacl

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

type dbKind uint8

const (
	dbCountry dbKind = iota + 1
	dbASN
)

func (k dbKind) String() string {
	if k == dbASN {
		return "asn"
	}
	return "country"
}

func (k dbKind) option() string {
	if k == dbASN {
		return "db_asn"
	}
	return "db_country"
}

// A replaced reader is simply garbage-collected once in-flight requests are
// done with it; that is only safe because readers are not mmap-backed.
type dbHolder struct {
	kind dbKind
	path string
	cur  atomic.Pointer[dbHandle]
}

type dbHandle struct {
	reader *maxminddb.Reader
	stat   os.FileInfo
	dbType string
	built  time.Time
}

// The file is read into memory instead of mmapped: a file truncated or
// rewritten in place would crash an mmapped reader with SIGBUS. Verify makes
// a corrupt file fail here instead of at request time.
func loadDB(kind dbKind, path string) (*dbHandle, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kind.option(), err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kind.option(), err)
	}
	r, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", kind.option(), path, err)
	}
	dbType := r.Metadata.DatabaseType
	if err := checkDBType(kind, dbType); err != nil {
		return nil, fmt.Errorf("%s: %s: %w", kind.option(), path, err)
	}
	if err := r.Verify(); err != nil {
		return nil, fmt.Errorf("%s: %s: invalid database: %w", kind.option(), path, err)
	}
	return &dbHandle{reader: r, stat: st, dbType: dbType, built: r.Metadata.BuildTime()}, nil
}

// City databases also carry country.iso_code, so they work in the country
// slot.
func checkDBType(kind dbKind, dbType string) error {
	t := strings.ToLower(dbType)
	isASN := strings.Contains(t, "asn")
	isCountry := !isASN && (strings.Contains(t, "country") || strings.Contains(t, "city"))
	switch {
	case kind == dbCountry && !isCountry:
		return fmt.Errorf("database type %q is not a country or city database", dbType)
	case kind == dbASN && !isASN:
		return fmt.Errorf("database type %q is not an ASN database", dbType)
	}
	return nil
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
}

type asnRecord struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
}

var errNoDB = errors.New("database not loaded")

func (h *dbHolder) lookupCountry(addr netip.Addr) (countryResult, error) {
	if h == nil || h.cur.Load() == nil {
		return countryResult{}, errNoDB
	}
	res := h.cur.Load().reader.Lookup(addr)
	if err := res.Err(); err != nil {
		return countryResult{}, err
	}
	if !res.Found() {
		return countryResult{}, nil
	}
	var rec countryRecord
	if err := res.Decode(&rec); err != nil {
		return countryResult{}, err
	}
	return countryResult{
		found:     rec.Country.ISOCode != "",
		country:   strings.ToUpper(rec.Country.ISOCode),
		continent: strings.ToUpper(rec.Continent.Code),
	}, nil
}

func (h *dbHolder) lookupASN(addr netip.Addr) (asnResult, error) {
	if h == nil || h.cur.Load() == nil {
		return asnResult{}, errNoDB
	}
	res := h.cur.Load().reader.Lookup(addr)
	if err := res.Err(); err != nil {
		return asnResult{}, err
	}
	if !res.Found() {
		return asnResult{}, nil
	}
	var rec asnRecord
	if err := res.Decode(&rec); err != nil {
		return asnResult{}, err
	}
	// ASN 0 is reserved and is what an entry without the field decodes to.
	return asnResult{found: rec.ASN != 0, asn: rec.ASN}, nil
}

type geoDBs struct {
	country *dbHolder
	asn     *dbHolder
}

func (g geoDBs) lookupCountry(addr netip.Addr) (countryResult, error) {
	return g.country.lookupCountry(addr)
}

func (g geoDBs) lookupASN(addr netip.Addr) (asnResult, error) {
	return g.asn.lookupASN(addr)
}
