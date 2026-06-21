[] take all the structs and define to header file .h file and import it. 

[] maybe put the functions declerations in a header file.

[] add command-line flag options (--verbose, --filter ...)

[] make the hashing function less prone to collisions

[] remove part# as comments and instead write descriptive comments

[] add testing to the project and then explain how to use them in the README.md file !!

    C unit tests (test.c):
    [] test hash_flow: same key always returns same hash
    [] test hash_flow: different src_ip/dst_ip produce different hashes (no trivial collision)
    [] test keys_match: returns 1 for identical keys
    [] test keys_match: returns 0 when any field differs (src_ip, dst_ip, ports, proto)
    [] test update_flow: new flow inserted with packets=1, bytes=packet_size
    [] test update_flow: existing flow increments packets and bytes correctly
    [] test update_flow: returns -1 when table is full
    [] add "make test" target to Makefile that compiles test.c and runs it

    Python integration tests (test_integration.py):
    [] pip install scapy
    [] launch ./sniffer in a subprocess, listening on loopback (lo)
    [] use scapy to send a crafted TCP/UDP packet to 127.0.0.1
    [] read ./sniffer stdout and assert the expected 5-tuple appears in the output
    [] assert packet count and byte count match what was sent
    [] send 2 packets on the same flow, assert packet count increments to 2
    [] send packets from two different flows, assert both appear in output
    [] add test instructions to README.md

[] if the table is full -> make s.t. new ones will replace the least active flow (or old ones)

[] support for ipv6 in addition to ipv4

[] BPF-style filtering

[] PCAP export

[] Flow timeout/expiry

[x] sort table and live print the top used 20 connections.



--------------------------------

## from claude:

### Do first (structure and polish):

Multi-file split (headers + modules) — shows you know project organization
Remove part# comments, write descriptive ones — cleaner code
Makefile update for multi-file compilation

### Do second (impressive features):

4. Command-line flags — shows you know getopt

5. Flow timeout/expiry — directly relevant to DOCA

6. Better hash function — shows you think about performance
Do later (nice to have):

7. Testing

8. IPv6 support

9. PCAP export

10. BPF filtering

11. Table eviction