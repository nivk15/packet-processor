# Packet Processor

A user-space network packet sniffer and flow classifier built from scratch in C using Linux raw sockets.

Captures live network traffic, parses protocol headers (Ethernet, IP, TCP, UDP, ICMP), classifies packets into flows by 5-tuple, and displays a live-updating dashboard of the busiest network conversations sorted by bytes transferred.

## Features

- Raw packet capture using `AF_PACKET` sockets — no external libraries
- Protocol parsing: Ethernet, IPv4, TCP, UDP, ICMP
- Flow classification by 5-tuple (src IP, dst IP, src port, dst port, protocol)
- Hash table with linear probing for flow tracking
- Live terminal dashboard showing top 20 flows sorted by bytes
- Clean exit on `Ctrl+C` with full flow summary
- Async-signal-safe signal handling using `sigaction`

## Build

```bash
make
```

## Usage

Requires root privileges for raw socket access:

```bash
sudo ./sniffer
```

Press `Ctrl+C` to stop and display the full flow summary.

## Example Output

### Live Dashboard
```
SRC IP:PORT               DST IP:PORT               PROTO    PKTS     BYTES      DURATION
127.0.0.1:32843           127.0.0.1:47244           TCP      5338     12340472   15s
142.251.157.119:80        172.19.154.29:50196       TCP      35       87521      0s
172.19.154.29:50196       142.251.157.119:80        TCP      36       1970       0s
10.255.255.254:53         10.255.255.254:59588      UDP      4        944        0s
172.19.154.29:0           8.8.8.8:0                 ICMP     9        756        9s
```

### Exit Summary
```
(Total flows tracked: 39)
```

## How It Works

1. **Capture** — Opens a raw socket with `AF_PACKET` to receive all network traffic as raw bytes
2. **Parse Ethernet** — Reads the first 14 bytes to extract MAC addresses and EtherType, filters for IPv4 (`0x0800`)
3. **Parse IP** — Overlays `struct iphdr` at byte 14 to extract source/destination IPs, protocol, and packet length
4. **Parse TCP/UDP** — Overlays `struct tcphdr` or `struct udphdr` at the calculated offset to extract port numbers
5. **Track Flows** — Hashes the 5-tuple (src IP, dst IP, src port, dst port, protocol) and stores per-flow statistics in a hash table with linear probing
6. **Display** — Clears the terminal and reprints the flow table sorted by bytes after every packet, creating a live dashboard

## Project Structure

```
├── main.c        — capture loop, signal handling, packet parsing
├── flow.h        — structs, defines, and function declarations
├── flow.c        — flow table logic (hash, insert, update, display)
└── Makefile
```