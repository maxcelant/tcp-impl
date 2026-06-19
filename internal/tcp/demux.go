package tcp

import (
	"net/netip"
	"sync"
)

type connKey struct {
	local  netip.AddrPort
	remote netip.AddrPort
}

type demux struct {
	mu sync.RWMutex
	m  map[connKey]*Conn
}

func NewDemux() *demux {
	return &demux{m: make(map[connKey]*Conn)}
}

func (d *demux) Set(key connKey, v *Conn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.m[key]; ok {
		return false
	}
	d.m[key] = v
	return true
}

func (d *demux) Get(key connKey) (*Conn, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	v, ok := d.m[key]
	if !ok {
		return nil, false
	}
	return v, true
}

func (d *demux) Delete(key connKey) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.m, key)
}
