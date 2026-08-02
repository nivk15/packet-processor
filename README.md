# Packet Processor

A user-space network packet sniffer and flow classifier built from scratch in C using Linux raw sockets.

Captures live network traffic, parses protocol headers (Ethernet, IP, TCP, UDP, ICMP), classifies packets into flows by 5-tuple, and displays a live-updating dashboard of the busiest network conversations sorted by bytes transferred.

## Features

- Raw packet capture using `AF_PACKET` sockets — no external libraries
- Protocol parsing: Ethernet, IPv4, TCP, UDP, ICMP
- Flow classification by 5-tuple (src IP, dst IP, src port, dst port, protocol)
- Hash table with linear probing for flow tracking
- Live terminal dashboard showing top flows sorted by bytes (configurable with -n)
- Idle flow expiry with LRU slot reuse — flows quiet for 30s drop off the live view
- Clean exit on `Ctrl+C` with full flow summary
- Async-signal-safe signal handling using `sigaction`

## Build

```bash
make
```

## Usage

Requires root privileges for raw socket access.

To list available interfaces, run `ip link show`.

```bash
sudo ./sniffer                    # capture all interfaces
sudo ./sniffer -i eth0            # capture specific interface
sudo ./sniffer -i eth0 -n 10      # show top 10 flows
sudo ./sniffer --help             # show usage
```

Press `Ctrl+C` to stop and display the full flow summary.

## Options

```
-i, --interface   Network interface to capture on (e.g. eth0)
-n, --rows        Number of flows to display (default: 20)
-h, --help        Show this help message
```

## Example Output

### `sudo ./sniffer`
```
SRC IP:PORT               DST IP:PORT               PROTO    PKTS     BYTES      DURATION
127.0.0.1:40247           127.0.0.1:40132           TCP      3652     9027218    9s
127.0.0.1:40144           127.0.0.1:40247           TCP      1776     8865780    9s
127.0.0.1:40132           127.0.0.1:40247           TCP      3046     275024     9s
127.0.0.1:40247           127.0.0.1:40144           TCP      1772     160994     9s
172.19.154.29:47408       20.184.175.5:443          TCP      2        143        0s
20.184.175.5:443          172.19.154.29:47408       TCP      2        131        6s
40.79.163.154:443         172.19.154.29:34516       TCP      1        40         0s
```

### Exit Summary
```
(Total flows tracked: 7)
```

## How It Works

1. **Capture** — Opens a raw socket with `AF_PACKET` to receive all network traffic as raw bytes
2. **Parse Ethernet** — Reads the first 14 bytes to extract MAC addresses and EtherType, filters for IPv4 (`0x0800`)
3. **Parse IP** — Overlays `struct iphdr` at byte 14 to extract source/destination IPs, protocol, and packet length
4. **Parse TCP/UDP** — Overlays `struct tcphdr` or `struct udphdr` at the calculated offset to extract port numbers
5. **Track Flows** — Hashes the 5-tuple (src IP, dst IP, src port, dst port, protocol) and stores per-flow statistics in a hash table with linear probing
6. **Expire Idle Flows** — Flows with no packets for `FLOW_TIMEOUT` seconds are hidden from the live view and their slots become reusable. Slots are never cleared in place — removing an entry mid-chain would break linear probing and allow duplicate flows
7. **Display** — Redraws the whole table after every tracked packet, sorted by total bytes per flow, creating a live dashboard. The exit summary shows every flow still in the table, including expired ones

## Project Structure

```
├── main.c        — capture loop, signal handling, packet parsing
├── flow.h        — structs, defines, and function declarations
├── flow.c        — flow table logic (hash, insert, update, display)
└── Makefile
```