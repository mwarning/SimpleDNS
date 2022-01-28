
### Introduction

SimpleDNS is a very simple DNS server written in C.
It was made to learn the basics of the DNS protocol.

Features:
* very small
* single-threaded
* very simplistic memory management
* supports A, AAAA and TXT queries
* no full protection against invalid requests :|

### Build

```
git clone https://github.com/mwarning/SimpleDNS.git
cd SimpleDNS
make
```

### Test

Start SimpleDNS:
```
$./main
Listening on port 9000.
```

In another console execute [dig](http://linux.die.net/man/1/dig) to make a DNS request:

```
$ dig @127.0.0.1 -p 9000 foo.bar.com A

; <<>> DiG 9.8.4-rpz2+rl005.12-P1 <<>> @127.0.0.1 -p 9000 foo.bar.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR, id: 15287
;; flags: qr; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;foo.bar.com.                   IN      A

;; ANSWER SECTION:
foo.bar.com.            0       IN      A       192.168.1.1

;; Query time: 0 msec
;; SERVER: 127.0.0.1#9000(127.0.0.1)
;; WHEN: Mon Apr 15 00:50:38 2013
;; MSG SIZE  rcvd: 56
```

Note:
- On Debian Linux, dig is part of the dnsutils package.
- Use AAAA instead of A in the dig command line to request the IPv6 address.

## Modify address entries

The code maps the domain "foo.bar.com" to the IPv4 address 192.168.1.1 and IPv6 address fe80::1.
It is easy to find it in the code and to add other entries.

### Recommended Reading

The DNS section of the [TCP/IP-Guide](http://www.tcpipguide.com/free/t_TCPIPDomainNameSystemDNS.htm) was very helpful for understanding the protocol.

## Similar Projects

* https://github.com/wfelipe/simple-dns
