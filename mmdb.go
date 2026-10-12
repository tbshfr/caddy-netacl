package netacl

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
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
	// Only the cache for the handle's kind is set. Offsets are only valid
	// for one file, so each handle has its own.
	countries *recordCache[countryResult]
	asns      *recordCache[asnResult]
}

// recordCache memoizes decoded records by their offset in the data section.
// Networks share records (DB-IP Lite has 251 distinct country records for
// 1.4M networks, and 82k ASN records), so a small table spares most decodes.
// It is direct-mapped and lock-free: a collision simply replaces the slot.
type recordCache[T any] struct {
	shift uint
	slots []atomic.Pointer[cachedRecord[T]]
}

type cachedRecord[T any] struct {
	offset uintptr
	val    T
}

func newRecordCache[T any](bits uint) *recordCache[T] {
	return &recordCache[T]{shift: 64 - bits, slots: make([]atomic.Pointer[cachedRecord[T]], 1<<bits)}
}

func (c *recordCache[T]) slot(offset uintptr) *atomic.Pointer[cachedRecord[T]] {
	// Fibonacci hashing: offsets are not uniformly spread over the low bits.
	return &c.slots[(uint64(offset)*0x9E3779B97F4A7C15)>>c.shift]
}

func (c *recordCache[T]) get(offset uintptr) (T, bool) {
	if e := c.slot(offset).Load(); e != nil && e.offset == offset {
		return e.val, true
	}
	var zero T
	return zero, false
}

func (c *recordCache[T]) put(offset uintptr, v T) {
	c.slot(offset).Store(&cachedRecord[T]{offset: offset, val: v})
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
	h := &dbHandle{reader: r, stat: st, dbType: dbType, built: r.Metadata.BuildTime()}
	// Sized for the record counts above: the cache holds every country, and
	// the ASNs that real traffic concentrates on.
	if kind == dbASN {
		h.asns = newRecordCache[asnResult](13)
	} else {
		h.countries = newRecordCache[countryResult](10)
	}
	return h, nil
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
	var cur *dbHandle
	if h != nil {
		cur = h.cur.Load()
	}
	if cur == nil {
		return countryResult{}, errNoDB
	}
	res := cur.reader.Lookup(addr)
	if err := res.Err(); err != nil {
		return countryResult{}, err
	}
	if !res.Found() {
		return countryResult{}, nil
	}
	if c, ok := cur.countries.get(res.Offset()); ok {
		return c, nil
	}
	var rec countryRecord
	if err := res.Decode(&rec); err != nil {
		return countryResult{}, err
	}
	c := countryResult{
		found:     rec.Country.ISOCode != "",
		country:   strings.ToUpper(rec.Country.ISOCode),
		continent: strings.ToUpper(rec.Continent.Code),
	}
	cur.countries.put(res.Offset(), c)
	return c, nil
}

func (h *dbHolder) lookupASN(addr netip.Addr) (asnResult, error) {
	var cur *dbHandle
	if h != nil {
		cur = h.cur.Load()
	}
	if cur == nil {
		return asnResult{}, errNoDB
	}
	res := cur.reader.Lookup(addr)
	if err := res.Err(); err != nil {
		return asnResult{}, err
	}
	if !res.Found() {
		return asnResult{}, nil
	}
	if a, ok := cur.asns.get(res.Offset()); ok {
		return a, nil
	}
	var rec asnRecord
	if err := res.Decode(&rec); err != nil {
		return asnResult{}, err
	}
	// ASN 0 is reserved and is what an entry without the field decodes to.
	a := asnResult{found: rec.ASN != 0, asn: rec.ASN}
	if a.found {
		a.varValue = strconv.FormatUint(uint64(a.asn), 10)
	}
	cur.asns.put(res.Offset(), a)
	return a, nil
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
