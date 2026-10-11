package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// HostInfo is what we know about an address beyond its packets.
type HostInfo struct {
	Kind    string // public, LAN, loopback, multicast, broadcast, link-local, tailscale/CGNAT
	Name    string // reverse DNS
	Country string
	City    string
	Org     string // ISP / organisation
	ASN     string
	NameOK  bool // reverse DNS attempted
	GeoOK   bool // geo lookup finished (or not applicable)
	used    time.Time
}

// cacheIdle is how long an address stays cached after it was last displayed;
// maxCache bounds the cache during bursts of new addresses.
const (
	cacheIdle = 30 * time.Minute
	maxCache  = 2 * maxHosts
)

// Origin is a one-line description of where the address comes from.
func (h HostInfo) Origin() string {
	if h.Kind != "public" {
		return h.Kind
	}
	var parts []string
	if h.City != "" && h.Country != "" {
		parts = append(parts, h.City+", "+h.Country)
	} else if h.Country != "" {
		parts = append(parts, h.Country)
	}
	if h.Org != "" {
		parts = append(parts, h.Org)
	} else if h.ASN != "" {
		parts = append(parts, h.ASN)
	}
	if len(parts) == 0 {
		if h.GeoOK {
			return "public"
		}
		return "public (looking up…)"
	}
	return strings.Join(parts, " · ")
}

type Resolver struct {
	mu        sync.Mutex
	cache     map[netip.Addr]*HostInfo
	countries map[string]bool                                 // countries already announced
	onCountry func(country string, ip netip.Addr, org string) // first traffic with a country
	queue     chan netip.Addr
	webQ      chan netip.Addr
	online    bool
	city      *geoip2.Reader
	asn       *geoip2.Reader
	isLAN     func(netip.Addr) bool // broadcast detection from Agg
	// publicOnly skips reverse DNS for private addresses. In a replay they
	// belong to the recorded network, and this one's resolver would answer
	// with its own devices' names.
	publicOnly bool
	client     *http.Client
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func NewResolver(online bool, cityDB, asnDB string, isBroadcast func(netip.Addr) bool) (*Resolver, error) {
	r := &Resolver{
		cache:     map[netip.Addr]*HostInfo{},
		countries: map[string]bool{},
		queue:     make(chan netip.Addr, 8192),
		webQ:      make(chan netip.Addr, 4096),
		online:    online,
		isLAN:     isBroadcast,
		client:    &http.Client{Timeout: 6 * time.Second},
	}
	var err error
	if cityDB != "" {
		if r.city, err = geoip2.Open(cityDB); err != nil {
			return nil, fmt.Errorf("geoip db: %w", err)
		}
	}
	if asnDB != "" {
		if r.asn, err = geoip2.Open(asnDB); err != nil {
			return nil, fmt.Errorf("asn db: %w", err)
		}
	}
	for i := 0; i < 8; i++ {
		go r.rdnsWorker()
	}
	if online {
		go r.webWorker()
	}
	go r.pruneLoop()
	return r, nil
}

// pruneLoop drops addresses nobody has looked at for cacheIdle.
func (r *Resolver) pruneLoop() {
	for range time.Tick(time.Minute) {
		r.prune(time.Now())
	}
}

func (r *Resolver) prune(now time.Time) {
	r.mu.Lock()
	for ip, hi := range r.cache {
		if now.Sub(hi.used) > cacheIdle {
			delete(r.cache, ip)
		}
	}
	r.mu.Unlock()
}

// ResetCountries forgets which countries were announced.
func (r *Resolver) ResetCountries() {
	r.mu.Lock()
	clear(r.countries)
	r.mu.Unlock()
}

// noteCountry announces the first address seen from a country. Call without r.mu held.
func (r *Resolver) noteCountry(ip netip.Addr) {
	r.mu.Lock()
	hi, ok := r.cache[ip]
	if !ok || hi.Country == "" || r.countries[hi.Country] || r.onCountry == nil {
		r.mu.Unlock()
		return
	}
	r.countries[hi.Country] = true
	country, org := hi.Country, firstNonEmpty(hi.Org, hi.ASN)
	r.mu.Unlock()
	r.onCountry(country, ip, org)
}

func (r *Resolver) Close() {
	if r.city != nil {
		r.city.Close()
	}
	if r.asn != nil {
		r.asn.Close()
	}
}

func (r *Resolver) classify(ip netip.Addr) string {
	switch {
	case !ip.IsValid():
		return "?"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast():
		return "multicast"
	case r.isLAN != nil && r.isLAN(ip):
		return "broadcast"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case cgnat.Contains(ip):
		return "tailscale/CGNAT"
	case ip.IsPrivate():
		return "LAN"
	default:
		return "public"
	}
}

// Enqueue starts background lookups for a new address. Safe to call under Agg's lock.
func (r *Resolver) Enqueue(ip netip.Addr) {
	r.mu.Lock()
	if _, ok := r.cache[ip]; ok {
		r.mu.Unlock()
		return
	}
	hi := &HostInfo{Kind: r.classify(ip), used: time.Now()}
	public := hi.Kind == "public"
	hi.GeoOK = true
	if public {
		r.geoLookup(ip, hi)
		hi.GeoOK = !r.online || (hi.Country != "" && hi.Org != "")
	}
	// Reverse DNS for everything routable; skip multicast/broadcast noise.
	wantName := public || !r.publicOnly && (hi.Kind == "LAN" || hi.Kind == "tailscale/CGNAT")
	hi.NameOK = !wantName
	wantWeb := public && r.online && !hi.GeoOK
	r.cache[ip] = hi
	trimOldest(r.cache, maxCache, func(h *HostInfo) time.Time { return h.used })
	r.mu.Unlock()

	if wantName {
		select {
		case r.queue <- ip:
		default:
			r.set(ip, func(h *HostInfo) { h.NameOK = true })
		}
	}
	if wantWeb {
		select {
		case r.webQ <- ip:
		default:
			r.set(ip, func(h *HostInfo) { h.GeoOK = true })
		}
	}
	r.noteCountry(ip)
}

// Get returns a copy of what is known (zero value if nothing).
func (r *Resolver) Get(ip netip.Addr) HostInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	if hi, ok := r.cache[ip]; ok {
		hi.used = time.Now()
		return *hi
	}
	return HostInfo{Kind: r.classify(ip)}
}

func (r *Resolver) set(ip netip.Addr, fn func(*HostInfo)) {
	r.mu.Lock()
	if hi, ok := r.cache[ip]; ok {
		fn(hi)
	}
	r.mu.Unlock()
}

// geoLookup fills country/city/org from local MaxMind databases, if any.
func (r *Resolver) geoLookup(ip netip.Addr, hi *HostInfo) {
	nip := net.IP(ip.AsSlice())
	if r.city != nil {
		if strings.Contains(r.city.Metadata().DatabaseType, "City") {
			if rec, err := r.city.City(nip); err == nil {
				hi.Country = rec.Country.IsoCode
				hi.City = rec.City.Names["en"]
			}
		} else if rec, err := r.city.Country(nip); err == nil {
			hi.Country = rec.Country.IsoCode
		}
	}
	if r.asn != nil {
		if rec, err := r.asn.ASN(nip); err == nil {
			hi.Org = rec.AutonomousSystemOrganization
			if rec.AutonomousSystemNumber != 0 {
				hi.ASN = fmt.Sprintf("AS%d", rec.AutonomousSystemNumber)
			}
		}
	}
}

func (r *Resolver) rdnsWorker() {
	for ip := range r.queue {
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
		cancel()
		name := ""
		if err == nil && len(names) > 0 {
			name = strings.TrimSuffix(names[0], ".")
		}
		r.set(ip, func(h *HostInfo) {
			h.Name = name
			h.NameOK = true
		})
	}
}

// webWorker queries ip-api.com (free tier: 45 requests/minute, HTTP only).
func (r *Resolver) webWorker() {
	tick := time.NewTicker(1500 * time.Millisecond)
	defer tick.Stop()
	for ip := range r.webQ {
		<-tick.C
		info := ipAPI(r.client, ip)
		r.set(ip, func(h *HostInfo) {
			if info.Status == "success" {
				if h.Country == "" {
					h.Country = info.CountryCode
				}
				if h.City == "" {
					h.City = info.City
				}
				if h.Org == "" {
					h.Org = firstNonEmpty(info.ISP, info.Org)
				}
				if h.ASN == "" && info.AS != "" {
					h.ASN = strings.Fields(info.AS)[0]
				}
			}
			h.GeoOK = true
		})
		r.noteCountry(ip)
	}
}

type ipAPIResp struct {
	Status      string `json:"status"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`
}

func ipAPI(c *http.Client, ip netip.Addr) ipAPIResp {
	var out ipAPIResp
	url := "http://ip-api.com/json/" + ip.String() + "?fields=status,countryCode,city,isp,org,as"
	resp, err := c.Get(url)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
