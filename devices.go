package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

const (
	maxKnownDevices = 1024
	firstRunGrace   = 2 * time.Minute // on the very first run, learn silently for this long
	saveEvery       = time.Minute
)

// KnownDevice is what ears remembers about a LAN device between runs.
type KnownDevice struct {
	MAC    string    `json:"mac"`
	Name   string    `json:"name,omitempty"`
	IPs    []string  `json:"ips,omitempty"`
	Vendor string    `json:"vendor,omitempty"`
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
}

// DeviceBook persists known devices to a JSON file.
type DeviceBook struct {
	mu      sync.Mutex
	path    string // "" keeps the book in memory only
	devs    map[string]*KnownDevice
	quietTo time.Time // no "new device" notices before this
	dirty   bool
	savedAt time.Time
}

// LoadDeviceBook reads the book at path. A missing file starts a new book
// that stays quiet for firstRunGrace while it learns the network.
func LoadDeviceBook(path string) (*DeviceBook, error) {
	b := &DeviceBook{path: path, devs: map[string]*KnownDevice{}}
	if path == "" {
		b.quietTo = time.Now().Add(firstRunGrace)
		return b, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		b.quietTo = time.Now().Add(firstRunGrace)
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	var list []KnownDevice
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	for i := range list {
		b.devs[list[i].MAC] = &list[i]
	}
	return b, nil
}

// Observe records a sighting and reports whether the device is new and
// worth announcing.
func (b *DeviceBook) Observe(now time.Time, mac string, ips []netip.Addr, name, vendor string) (announce bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := b.devs[mac]
	if d == nil {
		if len(b.devs) >= maxKnownDevices {
			b.evictOldest()
		}
		d = &KnownDevice{MAC: mac, First: now}
		b.devs[mac] = d
		announce = now.After(b.quietTo)
		b.dirty = true
	}
	if now.Sub(d.Last) > saveEvery {
		d.Last = now
		b.dirty = true
	}
	if name != "" && name != d.Name {
		d.Name, b.dirty = name, true
	}
	if vendor != "" && vendor != d.Vendor {
		d.Vendor, b.dirty = vendor, true
	}
	for _, ip := range ips {
		s := ip.String()
		if !slices.Contains(d.IPs, s) {
			d.IPs = append([]string{s}, d.IPs...)[:min(len(d.IPs)+1, 4)]
			b.dirty = true
		}
	}
	return announce
}

func (b *DeviceBook) evictOldest() {
	var oldest *KnownDevice
	for _, d := range b.devs {
		if oldest == nil || d.Last.Before(oldest.Last) {
			oldest = d
		}
	}
	delete(b.devs, oldest.MAC)
}

// Get returns the remembered device for mac.
func (b *DeviceBook) Get(mac string) (KnownDevice, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if d, ok := b.devs[mac]; ok {
		return *d, true
	}
	return KnownDevice{}, false
}

// SaveIfDue writes the book when it changed and saveEvery has passed, or always when force is set.
func (b *DeviceBook) SaveIfDue(now time.Time, force bool) error {
	b.mu.Lock()
	if b.path == "" || !b.dirty || (!force && now.Sub(b.savedAt) < saveEvery) {
		b.mu.Unlock()
		return nil
	}
	list := make([]KnownDevice, 0, len(b.devs))
	for _, mac := range slices.Sorted(maps.Keys(b.devs)) {
		list = append(list, *b.devs[mac])
	}
	b.dirty, b.savedAt = false, now
	b.mu.Unlock()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}
