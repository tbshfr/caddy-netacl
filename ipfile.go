package netacl

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync/atomic"

	"github.com/gaissmai/bart"
)

type ipList struct {
	path string
	cur  atomic.Pointer[ipListData]
}

type ipListData struct {
	table *bart.Lite
	stat  os.FileInfo
	count int
}

func (l *ipList) contains(addr netip.Addr) bool {
	return l.cur.Load().table.Contains(addr)
}

func loadIPList(path string) (*ipListData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ip_file: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("ip_file: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("ip_file %s: is a directory", path)
	}
	d, err := parseIPList(f, path, nil)
	if err != nil {
		return nil, fmt.Errorf("ip_file %w", err)
	}
	d.stat = st
	return d, nil
}

// parseIPList reads one IP or CIDR per line. Errors start with name and the
// line number. check, if set, can reject individual prefixes.
func parseIPList(r io.Reader, name string, check func(netip.Prefix) error) (*ipListData, error) {
	d := &ipListData{table: new(bart.Lite)}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if i := bytes.IndexByte(b, '#'); i >= 0 {
			b = b[:i]
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			continue
		}
		p, err := ParsePrefix(string(b))
		if err == nil && check != nil {
			err = check(p)
		}
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, line, err)
		}
		d.table.Insert(p)
		d.count++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s:%d: %w", name, line+1, err)
	}
	return d, nil
}

// The inode is compared too, because a replacement copied with preserved
// timestamps can have the same size and mtime.
func fileChanged(old, cur os.FileInfo) bool {
	return !os.SameFile(old, cur) || !old.ModTime().Equal(cur.ModTime()) || old.Size() != cur.Size()
}
