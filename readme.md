<div align = "center"><img src="images/icon.png" width="256" height="256" /></div>

<div align = "center">
  <h1>Durian.cr - Domain Name System Resolver</h1>
</div>

<p align="center">
  <a href="https://crystal-lang.org">
    <img src="https://img.shields.io/badge/built%20with-crystal-000000.svg" /></a>    
  <a href="https://github.com/636f7374/durian.cr/actions">
    <img src="https://github.com/636f7374/durian.cr/workflows/Continuous%20Integration/badge.svg" /></a>
  <a href="https://github.com/636f7374/durian.cr/releases">
    <img src="https://img.shields.io/github/release/636f7374/durian.cr.svg" /></a>
  <a href="https://github.com/636f7374/durian.cr/blob/master/license">
    <img src="https://img.shields.io/github/license/636f7374/durian.cr.svg"></a>
</p>

## Description

* Because [Crystal Domain Name Resolver](https://github.com/crystal-lang/crystal/blob/master/src/socket/addrinfo.cr) uses `C.getaddrinfo`, It seems to have serious problems.
  * [This may cause the program to Freeze](https://github.com/crystal-lang/crystal/issues/8376), so I created this repository.  
* Of course, Crystal official is [always busy](#related), it will not help you solve these problems.
  * Thanks to [rdp](https://github.com/rdp) for the help, this made me sure that the problem was caused by `C.getaddrinfo`.
* Then I discovered the [CrDNS](https://github.com/teknomunk/cr-dns) repository, but it too broken, so I gave up the idea.
  * I started looking at [many documents](#references) and started researching how to build a DNS resolver.
  * It took me some time to make it, it's not troublesome, it's not easy.
* That's it, Thanks for using, If you encounter any problems, please let me know.

## Features

* If sending fails, it will try to resend through the next DNS server.
* It supports Querying / Receiving multiple DNS record Types.
  * AAAA
  * A
  * NS
  * PTR
  * SOA
  * TXT
  * MX
  * CNAME
  * DNAME
  * SRV
* It supports TCP and UDP protocols DNS server.
* It does not contain any `C.getaddrinfo`.
* It supports simple DNS caching (non-LRUCache).
  * (tapCount + updatedAt) custom Cache.
* You can send / receive packets via `Resolver`.
  * or you can process packets via `Packet.from_io`, `Packet.to_io`.
* ...

## Tips

* If the connection fails or there is no response packet, it will try to use the next server.
* `C.getaddrinfo` is incompatible with green threads, It may cause your program to [pause](#related).
  * `C.getaddrinfo` is too bad, you should not use it in green thread.
  * (libuv `uv_getaddrinfo`, libevent `evdns_getaddrinfo`) is too complicated, you may encounter many problems.

## Next

* [X] Support Alias & Mapping and Special DNS Server.
* [ ] Support response packet `to_io` operation.
* [ ] More exception handling.
* [ ] Support DNS server features.
* [ ] Better performance, Better DNS cache.
* [X] Supported DNS over TLS (DoT) feature.

## Usage

* Client | Http - Testing DNS resolution for IP availability.

```crystal
require "durian"

servers = [] of Durian::Resolver::Server
servers << Durian::Resolver::Server.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), protocol: Durian::Protocol::UDP
servers << Durian::Resolver::Server.new ipAddress: Socket::IPAddress.new("1.1.1.1", 53_i32), protocol: Durian::Protocol::UDP

buffer = uninitialized UInt8[4096_i32]
resolver = Durian::Resolver.new servers
resolver.ip_cache = Durian::Cache::IPAddress.new

begin
  socket = Durian::TCPSocket.connect "www.example.com", 80_i32, resolver, 5_i32
  socket.read_timeout = 5_i32
  socket.write_timeout = 5_i32
rescue
  abort "Connect Failed"
end

begin
  socket << "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"
rescue
  abort "Write Failed"
end

begin
  length = socket.read buffer.to_slice
rescue
  abort "Read Failed"
end

STDOUT.puts [length, String.new buffer.to_slice[0_i32, length]]
```

* Client | Query - A similar [React](https://reactphp.org/dns/) Proc usage.

```crystal
require "durian"

servers = [] of Durian::Resolver::Server
servers << Durian::Resolver::Server.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), protocol: Durian::Protocol::UDP
servers << Durian::Resolver::Server.new ipAddress: Socket::IPAddress.new("1.1.1.1", 53_i32), protocol: Durian::Protocol::UDP

resolver = Durian::Resolver.new servers
resolver.record_cache = Durian::Cache::Record.new

resolver.resolve "google.com", [Durian::RecordFlag::A, Durian::RecordFlag::AAAA] do |response|
  STDOUT.puts [:Google, Time.utc, response]
end

resolver.resolve "twitter.com", Durian::RecordFlag::SOA do |response|
  STDOUT.puts [:Twitter, Time.utc, response]
end

resolver.resolve "facebook.com", [Durian::RecordFlag::A, Durian::RecordFlag::AAAA] do |response|
  STDOUT.puts [:FaceBook, Time.utc, response]
end

resolver.resolve "twitter.com", Durian::RecordFlag::SOA do |response|
  STDOUT.puts [:Twitter, Time.utc, response]
end

resolver.run
```

* Client | Packet - from_io, to_io usage.

```crystal
require "durian"

buffer = uninitialized UInt8[4096_i32]

request = Durian::Packet.new Durian::Protocol::UDP, Durian::Packet::QRFlag::Query
request.add_query "www.example.com", Durian::RecordFlag::A

_request = IO::Memory.new request.to_slice
STDOUT.puts [:Request, Durian::Packet.from_io Durian::Protocol::UDP, _request]

udp_socket = UDPSocket.new
udp_socket.connect Socket::IPAddress.new "8.8.8.8", 53_i32
udp_socket.send _request.to_slice
length, ip_address = udp_socket.receive buffer.to_slice

_response = IO::Memory.new buffer.to_slice[0_i32, length]
STDOUT.puts [:Response, Durian::Packet.from_io Durian::Protocol::UDP, _response]
```

### Used as Shard

Add this to your application's shard.yml:
```yaml
dependencies:
  durian:
    github: 636f7374/durian.cr
```

### Installation

```bash
$ git clone https://github.com/636f7374/durian.cr.git
```

## Development

```bash
$ make test
```

## References

* [StackOverflow | How to convert a string or integer to binary in Ruby?](https://stackoverflow.com/questions/2339695/how-to-convert-a-string-or-integer-to-binary-in-ruby)
* [StackOverflow | Requesting A and AAAA records in single DNS query](https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query)
* [StackOverflow | Example of DNS Compression Pointer Offset > than 12 bytes](https://stackoverflow.com/questions/39439283/example-of-dns-compression-pointer-offset-than-12-bytes)
* [StackOverflow | why libuv do DNS request by multiple thread](https://stackoverflow.com/questions/44603059/why-libuv-do-dns-request-by-multiple-thread)
* [Official | DNS_HEADER structure](https://docs.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_header)
* [Official | The Saga of Concurrent DNS in Python, and the Defeat of the Wicked Mutex Troll](https://engineering.mongodb.com/post/the-saga-of-concurrent-dns-in-python-and-the-defeat-of-the-wicked-mutex-troll)
* [Official | Help understanding DNS packet data](https://osqa-ask.wireshark.org/questions/50806/help-understanding-dns-packet-data)
* [Official | Ietf - RFC 1035](https://www.ietf.org/rfc/rfc1035.txt)
* [Official | Docs.rs::hyper_trust_dns_connector](https://docs.rs/hyper-trust-dns-connector/0.1.0/hyper_trust_dns_connector/)
* [Official | libuv provides asynchronous variants of getaddrinfo and getnameinfo](http://docs.libuv.org/en/v1.x/dns.html)
* [Blogs | Adventures in Rust: Futures and Tokio](https://bryangilbert.com/post/code/rust/adventures-futures-tokio-rust/)
* [Blogs | Cocoa: Asynchronous Host name lookups](https://eggerapps.at/blog/2014/hostname-lookups.html)
* [Blogs | Using DNS with Libevent: high and low-level functionality](http://www.wangafu.net/~nickm/libevent-book/Ref9_dns.html)
* [Blogs | The problem with libresolv](https://skarnet.org/software/s6-dns/libresolv.html)
* [Blogs | The problem with getaddrinfo](https://skarnet.org/software/s6-dns/getaddrinfo.html)
* [Blogs | What does getaddrinfo do?](https://jameshfisher.com/2018/02/03/what-does-getaddrinfo-do/)
* [Blogs | A warm welcome to DNS](https://powerdns.org/hello-dns/basic.md.html)
* [Document | DNS Query Message Format](http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/160-protocols-dns-query.html)
* [Docuemnt | Protocol and Format](http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html)
* [Document | Binary Numbers](http://www.oualline.com/practical.programmer/numbers.html)
* [Document | DNS Message Header and Question Section Format](http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm)
* [Document | DNS Name Notation and Message Compression Technique](http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique-2.htm)
* [Github Gist | DNS Query Code in C with linux sockets](https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168)
* [Github Gist | getaddrinfo.strace](https://gist.github.com/alq666/4683879)
* [Source Code | posix/getaddrinfo.c](https://code.woboq.org/userspace/glibc/sysdeps/posix/getaddrinfo.c.html#getaddrinfo)
* [Source Code | DNS header for C | 0x00sec](https://0x00sec.org/t/dns-header-for-c/618)
* ...

## Related

* [#8480 | blocking call in one fiber can cause IO timeouts in others](https://github.com/crystal-lang/crystal/issues/8480)
* [#4816 | Add Resolv class to standard library](https://github.com/crystal-lang/crystal/issues/4816)
* [#2660 | Fix/Implement own DNS resolver](https://github.com/crystal-lang/crystal/issues/2660)
* [#4236 | Configurable DNS resolvers](https://github.com/crystal-lang/crystal/pull/4236)
* [#2829 | DNS threaded resolver](https://github.com/crystal-lang/crystal/pull/2829)
* [#2745 | Don't use libevent's getaddrinfo, use C's getaddrinfo](https://github.com/crystal-lang/crystal/pull/2745)
* [#8376 | Some TCPSocket connections will cause HTTP::Server accept (freeze | blocking | hangs | waiting)?](https://github.com/crystal-lang/crystal/issues/8376)
* ...

## Credit

* [\_Icon::Wanicon/Fruits](https://www.flaticon.com/packs/fruits-and-vegetables-48)
* [\_Icon::Freepik/GraphicDesign](https://www.flaticon.com/packs/graphic-design-125)

## Contributors

|Name|Creator|Maintainer|Contributor|
|:---:|:---:|:---:|:---:|
|**[636f7374](https://github.com/636f7374)**|√|√||
|**[rdp](https://github.com/rdp)**|||√|
|**[teknomunk](https://github.com/teknomunk)**|||√|
|**[ilmanzo](https://github.com/ilmanzo)**|||√|
|**[yunixon](https://github.com/yunixon)**|||√|
|**[z64](https://github.com/z64)**|||√|

## License

* MIT License
