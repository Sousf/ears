# ears

A terminal traffic monitor. It captures the packets reaching one network
interface and shows who is talking to this machine, from where.

![ears replaying a made-up capture: flows, hosts, packets, DNS, stats, notices and the map](demo.gif)

The recording replays `testdata/demo.pcap`, made-up traffic on a documentation
network. `vhs demo.tape` re-records it.

## Install

```bash
brew install sousf/tap/ears
sudo setcap cap_net_raw,cap_net_admin=eip "$(brew --prefix)/opt/ears/bin/ears"
ears
```

Homebrew builds `ears` from source, pulling in Go and libpcap. The `setcap`
line lets it capture without `sudo` on Linux; on macOS, run `sudo ears`.
Redo `setcap` after every `brew upgrade`, since the capability is attached to
the file.

From a clone instead (needs Go and `libpcap-dev`):

```bash
go build -o ears .
sudo setcap cap_net_raw,cap_net_admin=eip ./ears
./ears
```

Without capture rights `ears` exits with `Permission Denied` and prints the
`setcap` command. Replaying a file with `-r` needs no rights at all.

## Run

With no flags, `ears` captures on the interface carrying the default route.
`ears -list` prints the others, and `ears -h` every flag.

```bash
ears -i tailscale0                 # a specific interface
ears -f 'not port 22'              # any BPF filter, tcpdump syntax
ears -w capture.pcap               # also save every frame for Wireshark
ears -r capture.pcap -speed 4      # replay a saved capture, four times faster
ears -online                       # country and ISP via ip-api.com
ears -ai                           # press a to have Claude explain a row
```

## Views

Switch with `Tab` or `1` to `7`. `?` in the app lists every key and column.

| View    | One row per                  | What it adds                                                                       |
| ------- | ---------------------------- | ---------------------------------------------------------------------------------- |
| Flows   | remote ip:port to local port | process, server name, handshake RTT, TTL; `t` opens a timeline                     |
| Hosts   | remote address               | totals, top ports, processes, best name, origin                                    |
| Packets | captured frame, newest first | TCP flags, TLS server name, HTTP request, DNS; `Enter` decodes                     |
| DNS     | name looked up               | lookup count, answers, network behind them, program; `Enter` for details           |
| Stats   | (charts)                     | 60 s bandwidth sparklines, bytes by protocol, port, process, country, organisation |
| Map     | (diagram)                    | the router, LAN devices, Wi-Fi link and every hop to the internet                  |
| Notices | event                        | first traffic to a country, inbound connections, port scans, ARP changes           |

Direction is relative to this machine: `in` is addressed to one of its IPs,
`out` leaves from one, `other` is overheard broadcast, multicast or mirrored
traffic. `Enter` in Flows and Hosts opens the address's names, reverse DNS,
origin, MAC, hop estimate and ports.

The NAME column takes the TLS server name, else the HTTP `Host` header, else a
DNS reply captured while `ears` was running. PROCESS reads `/proc`, so it only
sees your own user's programs unless `ears` runs under `sudo`; `-no-proc`
turns it off.

On the Map, arrow keys or `j`/`k` move between boxes and `Enter` opens one.
The route trace to 1.1.1.1 runs once when the tab opens; `u` reruns it,
`-trace` changes the target and `-no-trace` disables it. LAN devices are
remembered in `~/.local/share/ears/devices.json`, and one never seen before
raises a `device` notice. `-devices none` turns that off.

## Ask Claude

`ears -ai`, then `a` on a row in Flows, Hosts, Packets, Notices or the Map
(`A` for the whole map). An explanation of under 80 words streams into a panel
after about 4 seconds. `v` shows the exact text sent: only the selected row.
Without `-ai`, nothing is sent.

| `-ai-backend` | Uses                                                | Billing                         |
| ------------- | --------------------------------------------------- | ------------------------------- |
| `claude-code` | a headless `claude -p` run, with all tools off      | your Claude Pro or Max plan     |
| `api`         | Anthropic's API directly, needs `ANTHROPIC_API_KEY` | per request, about 1 to 5 cents |

The default, `auto`, picks `api` when `ANTHROPIC_API_KEY` is set. `-ai-model`
overrides the model. Answers can be wrong, most often about who owns an
obscure server.

## Replay a capture

```bash
ears -r capture.pcap              # at the recorded pace
ears -r capture.pcap -speed 0     # as fast as the file reads
```

`-r` reads pcap or pcapng through the same views. `ears` takes the IPv4
address in the most frames as the recording machine and its /24 as the LAN.
Anything about the replaying machine stays off: processes, the route trace,
Wi-Fi, Tailscale and the known-devices file. `go run ./cmd/demopcap`
regenerates `testdata/demo.pcap`.

## Locate public addresses

```bash
mkdir -p ~/.local/share/ears
curl -L https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz | gunzip > ~/.local/share/ears/city.mmdb
curl -L https://download.db-ip.com/free/dbip-asn-lite-2026-10.mmdb.gz  | gunzip > ~/.local/share/ears/asn.mmdb
```

About 130 MB, under a minute. Once loaded, the origin column reads
`City, CC · Organisation`. DB-IP publishes monthly, so bump the date to
refresh. MaxMind GeoLite2 files work via `-geoip` and `-asn`.

`-online` asks ip-api.com instead, one address every 1.5 seconds. Every public
address you see is sent there.

A location is where the address block is registered or routed: for a CDN, the
datacenter; for a home connection, the ISP's nearest hub.

## What it can see

Only what reaches its interface. On a switched network that is this machine's
own traffic plus LAN broadcasts and multicast. To see everything through the
router, mirror a router port to this machine, or run `ears` on the router.

Memory stays flat: idle flows expire after 10 minutes and hosts after 30.
Two hours of constant churn settle at about 20 MB.
