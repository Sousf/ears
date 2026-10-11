# ears

A terminal traffic monitor. It captures the packets reaching one network
interface and shows who is talking to this machine, from where.

![ears replaying a made-up capture: flows, hosts, packets, DNS, stats, notices and the map](demo.gif)

The recording replays `testdata/demo.pcap`, made-up traffic on a documentation
network. `vhs demo.tape` re-records it.

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
./ears -r capture.pcap                     # replay a saved capture, no setcap needed
```

## Views

Seven views, switched with `Tab` or `1` to `7`. Press `?` in the app for the
full key and column reference.

| View    | One row per                  | What it adds                                                                       |
| ------- | ---------------------------- | ---------------------------------------------------------------------------------- |
| Flows   | remote ip:port to local port | process, server name, handshake RTT, TTL; `t` opens a timeline                     |
| Hosts   | remote address               | totals, top ports, processes, best name, origin                                    |
| Packets | captured frame, newest first | TCP flags, TLS server name, HTTP request, DNS; `Enter` decodes                     |
| DNS     | name looked up               | lookup count, answers, network behind them, program; `Enter` for details           |
| Stats   | (charts)                     | 60 s bandwidth sparklines, bytes by protocol, port, process, country, organisation |
| Map     | (diagram)                    | the router, LAN devices, Wi-Fi link and every hop to the internet                  |
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

### DNS

The DNS tab lists every name this machine looked up: how often, what it
resolved to, the network behind the answer, and the program that asked when
`ears` can tell. Failed lookups show in red. `s` sorts by last seen, count or
name.

With systemd-resolved, programs send lookups to `127.0.0.53` over loopback,
so `ears` also watches `lo` for DNS and logs every lookup, cache hits
included. The tab header says which source it is using. Program names often
show `-`, because resolver sockets close within milliseconds.

### Map

The Map tab draws the network this machine sits on, top to bottom: the
internet, each router on the way out, your router, the link to it, and every
device on the LAN. Markers move along the path while traffic flows, upward for
traffic leaving and downward for traffic arriving.

| Part        | Where it comes from                                                       |
| ----------- | ------------------------------------------------------------------------- |
| Router      | the default route in `/proc/net/route`                                    |
| Devices     | the kernel ARP table, plus any device the capture saw on the LAN          |
| Makers      | the IEEE vendor list in `/usr/share/hwdata/oui.txt` (package `hwdata`)    |
| Names       | DHCP hostnames and mDNS `.local` names seen in the capture, reverse DNS   |
| Wi-Fi       | `iwctl`, else `nmcli`, else just the signal from `/proc/net/wireless`     |
| Path out    | `tracepath` to 1.1.1.1, run once when the tab first opens; `u` reruns it  |
| Tailscale   | `tailscale status`, when Tailscale is running                             |

A device shows up once it has talked recently enough to be in the ARP table,
so a phone asleep on the network can be missing. Phones and laptops often use
a randomised MAC, shown as "private MAC", which hides the maker. Names fill in
as devices announce themselves, so a map left open for a few minutes is more
complete than a fresh one.

The trace sends a few dozen small UDP probes with rising TTLs; `-trace` picks
another target and `-no-trace` stops it running on its own. Routers past a
certain point often ignore probes, and the trace stops after three silent
hops.

`j`, `k` and the arrow keys move a highlight around the map: up and down in
reading order, left and right between boxes on the same row. The map scrolls
to follow it. `Enter` opens the selected item's details:

| Item      | Details                                                                         |
| --------- | ------------------------------------------------------------------------------- |
| Device    | names, addresses, MAC and maker, traffic, conversations, what its ports suggest |
| Router    | its role, latency, which radio is the access point, whether it answers DNS      |
| Hop       | operator, location, round trip, and how the trace found it                      |
| Internet  | public address, ISP, DNS servers, top networks and countries                    |
| Tailscale | status, addresses, and whether traffic goes direct or through a relay           |

`a` asks Claude about the selected item and `A` about the whole map.

### Known devices

`ears` remembers LAN devices in `~/.local/share/ears/devices.json`: name,
addresses, maker, and when it first and last saw each one. Names learned once
stay on the map in later runs, and a device it has never seen raises a
`device` notice. On the first run it learns the network quietly for two
minutes. `-devices none` turns this off; `-devices path` stores the file
elsewhere.

### Notices

| Kind      | Raised when                                                                         |
| --------- | ----------------------------------------------------------------------------------- |
| `country` | traffic involves a country for the first time this session                          |
| `inbound` | a public address sends a TCP SYN to this machine, at most once a minute per address |
| `scan`    | one address reaches 10 different local ports within 5 seconds                       |
| `arp`     | an IP address is claimed by a different MAC than before                             |
| `device`  | a LAN device appears that the known-devices file has never seen                     |

The newest notice also shows in the header for a minute. A changed MAC is
normal after replacing a router or device. Otherwise it can mean ARP spoofing.

### Ask Claude

```bash
./ears -ai
```

Press `a` on a row in Flows, Hosts, Packets or Notices and Claude explains it
in a panel, in under 80 words: what the traffic probably is and
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

### Replaying a capture

```bash
./ears -r capture.pcap              # at the recorded pace
./ears -r capture.pcap -speed 4     # four times faster
./ears -r capture.pcap -speed 0     # as fast as the file reads
```

`-r` runs a pcap or pcapng file through the same views as a live capture and
needs no `setcap`. Frames arrive at their recorded spacing, restamped to the
current time, so rates, sparklines and LAST behave as they do live. `-speed`
divides the spacing, and the round-trip times measured from it, by the same
factor. `-f` filters the file. The header shows `end of file` once the last
frame is in.

`ears` guesses the recording machine from the file: the IPv4 address in the
most frames. Its /24 is the LAN, and whatever it sends internet traffic
through is the router. Anything that would describe the machine doing the
replay stays off:

- no PROCESS column values
- no route trace, Wi-Fi or Tailscale on the Map
- the known-devices file is neither read nor written, so each device raises a
  `device` notice when it first appears
- reverse DNS for public addresses only, since private ones belong to the
  recorded network

`testdata/demo.pcap` is a minute of made-up traffic on a documentation
network. `go run ./cmd/demopcap` regenerates it.

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

## Memory

Memory stays flat on long runs. Flows expire after 10 idle minutes and hosts
after 30, with caps of 8,192 flows and 4,096 hosts; learned names and the DNS
log expire after an hour. Two hours of constant churn settle at about 20 MB.

## What this machine can and cannot see

`ears` sees what reaches its own interface. On a switched network that means
traffic to and from this machine, plus broadcasts and multicast from
everything else on the LAN. Traffic from the internet to the router that the
router does not forward here, and traffic between two other LAN devices, never
reaches this interface.

To watch everything that enters the router, mirror its WAN or LAN port to
this machine and run `ears` on the mirrored interface, or run `ears` on the router
itself if it runs Linux.
