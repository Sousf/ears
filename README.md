# ears

A terminal traffic monitor. It captures the packets reaching one network
interface and shows who is talking to this machine, from where.

## Run

```bash
go build -o ears .
sudo setcap cap_net_raw,cap_net_admin=eip ./ears
./ears
```

The `setcap` line grants the binary raw-socket rights so it runs without
`sudo`. Redo it after every rebuild, since the capability is attached to the
file. Without it `ears` exits with `Permission Denied` and prints the command.

With no flags, `ears` captures on the interface that carries the default route.
`./ears -list` prints the alternatives.

```bash
./ears -i tailscale0                       # a specific interface
./ears -f 'not port 22'                    # any BPF filter, tcpdump syntax
./ears -f 'dst host 192.168.1.117'         # inbound to this address only
./ears -w capture.pcap                     # also save every frame for Wireshark
./ears -online                             # country and ISP for public addresses
```

## Views

Five views, switched with `Tab` or `1` to `5`. Press `?` in the app for the
full key and column reference.

| View    | One row per                  | What it adds                                                                       |
| ------- | ---------------------------- | ---------------------------------------------------------------------------------- |
| Flows   | remote ip:port to local port | process, server name, handshake RTT, TTL; `t` opens a timeline                     |
| Hosts   | remote address               | totals, top ports, processes, best name, origin                                    |
| Packets | captured frame, newest first | TCP flags, TLS server name, HTTP request, DNS; `Enter` decodes                     |
| Stats   | (charts)                     | 60 s bandwidth sparklines, bytes by protocol, port, process, country, organisation |
| Notices | event                        | first traffic to a country, inbound connections, port scans, ARP changes           |

Direction is relative to this machine. `in` is addressed to one of its IPs,
`out` leaves from one, `other` is traffic it merely overheard: broadcasts,
multicast, and anything mirrored to the port.

In Flows and Hosts, `Enter` opens a detail panel for the selected address with
its names, reverse DNS, origin, MAC, estimated hop count and ports.

### Names

The NAME column shows what a program asked for, which is usually more useful
than the address. `ears` reads it from three places, best first:

1. The server name in a TLS ClientHello, sent in clear at the start of almost
   every HTTPS connection.
2. The `Host` header of a plaintext HTTP request.
3. A captured DNS reply that resolved some name to this address. This only
   works when the lookup happens while `ears` is running, and it misses
   programs using DNS over HTTPS.

Reverse DNS, shown in the detail panel as `rdns`, names whoever owns the
address block instead.

### Processes

The PROCESS column maps each local port to a program by reading `/proc`. It
sees your own user's processes. Connections from root daemons and other users
show `-` unless `ears` runs under `sudo`. A connection that opens and closes
within half a second can finish before the table refreshes. Turn it off with
`-no-proc`.

### Decode and timeline

`Enter` on a packet shows it layer by layer: Ethernet, IP, TCP or UDP, then
the application layer, one field per line, followed by a hex dump. Only the
first 2048 bytes of each frame are kept.

`t` on a TCP flow lists its packets in order with direction arrows, flags,
payload size and relative sequence numbers. The handshake, the round trip and
the close are labelled. Each flow records its first 200 packets.

### Notices

| Kind      | Raised when                                                                         |
| --------- | ----------------------------------------------------------------------------------- |
| `country` | traffic involves a country for the first time this session                          |
| `inbound` | a public address sends a TCP SYN to this machine, at most once a minute per address |
| `scan`    | one address reaches 10 different local ports within 5 seconds                       |
| `arp`     | an IP address is claimed by a different MAC than before                             |

The newest notice also shows in the header for a minute. A changed MAC is
normal after replacing a router or device. Otherwise it can mean ARP spoofing.

### Ask Claude

```bash
./ears -ai
```

Press `a` on a row in Flows, Hosts, Packets or Notices and Claude explains it
in a panel: what the traffic probably is, the concepts behind the values, and
whether anything looks off. Text starts after about 4 seconds and streams in.
`Esc` closes the panel and cancels the request.

`-ai` reaches Claude one of two ways, picked by `-ai-backend`:

| Backend       | Uses                                                | Billing                         |
| ------------- | --------------------------------------------------- | ------------------------------- |
| `claude-code` | a headless `claude -p` run, with all tools off      | your Claude Pro or Max plan     |
| `api`         | Anthropic's API directly, needs `ANTHROPIC_API_KEY` | per request, about 1 to 5 cents |

The default, `auto`, uses the API when `ANTHROPIC_API_KEY` is set and Claude
Code otherwise. The Claude Code backend needs `claude` on your `PATH` and
logged in; questions count toward your plan's usage limits. It uses Claude
Code's default model unless you pass `-ai-model`. The API backend defaults to
`claude-opus-5-5`, and refused requests are retried on a fallback model
automatically.

Each press sends one request describing only the selected row: addresses,
ports, server and process names, counters, origin, and for a packet its
decoded headers and first 128 bytes. In the panel, `v` shows the exact text
sent. Without `-ai`, nothing is ever sent.

Answers can be wrong, most often about what an obscure server belongs to.
Check a surprising claim against the data with `v`.

### Saving a capture

`-w file.pcap` writes every frame the `-f` filter lets through, whatever the
view, search or direction filter shows, so Wireshark or `tcpdump -r` can open
it. The file is flushed when
`ears` quits. It grows at whatever rate the link carries, so pair it with
`-f` on a busy interface.

## Where an address comes from

Every address gets a kind: `LAN`, `public`, `loopback`, `multicast`,
`broadcast`, `link-local` or `tailscale/CGNAT`. Routable addresses also get a
reverse DNS lookup.

Public addresses get a city, country and organisation when a database or the
online lookup is available. Neither is on by default.

### Local database

```bash
mkdir -p ~/.local/share/ears
curl -L https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz | gunzip > ~/.local/share/ears/city.mmdb
curl -L https://download.db-ip.com/free/dbip-asn-lite-2026-10.mmdb.gz  | gunzip > ~/.local/share/ears/asn.mmdb
```

About 130 MB, under a minute. `ears` loads both files from that directory on
start and every lookup is then local and instant. DB-IP publishes a new file
each month under the same URL pattern, so bump the date to refresh. MaxMind
GeoLite2 files work too, via `-geoip` and `-asn`, but need an account to
download.

The origin column reads `City, CC · Organisation` once the files load. If it
still says `public`, run `./ears -h`: the flag defaults name the paths checked.

### Online lookup

```bash
./ears -online
```

Asks ip-api.com for each public address, one request every 1.5 seconds, so a
busy capture fills in slowly. Every public address you see is sent to that
service.

### What a location means

IP geolocation names the place an address block is registered or routed, to
city precision at best. For a cloud or CDN address that is the datacenter, and
most of what a laptop talks to is a CDN node in or near your country, whatever
company is behind it. A residential address resolves to the ISP's nearest
hub, which can be a city away from the subscriber. Treat the result as "which
network, roughly where", never as a street.

## What this machine can and cannot see

`ears` sees what reaches its own interface. On a switched network that means
traffic to and from this machine, plus broadcasts and multicast from
everything else on the LAN. Traffic from the internet to the router that the
router does not forward here, and traffic between two other LAN devices, never
reaches this interface.

To watch everything that enters the router, mirror its WAN or LAN port to
this machine and run `ears` on the mirrored interface, or run `ears` on the router
itself if it runs Linux.
