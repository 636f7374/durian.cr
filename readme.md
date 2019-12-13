<div align = "center"><img src="images/icon.png" width="150" height="150" /></div>

<div align = "center">
  <h1>Durian.cr - DNS Resolver</h1>
</div>

<p align="center">
  <a href="https://crystal-lang.org">
    <img src="https://img.shields.io/badge/built%20with-crystal-000000.svg" /></a>
  <a href="https://travis-ci.org/636f7374/durian.cr">
    <img src="https://api.travis-ci.org/636f7374/durian.cr.svg" /></a>
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
* It supports TCP and UDP protocols DNS server.
* It does not contain any `C.getaddrinfo`.
* It supports simple DNS caching (non-LRUCache).
  * (tapCount + updatedAt) custom Cache.
* You can send / receive packets via `Resolver`.
  * or you can process packets via `Packet.from_io`, `Packet.to_io`.
* ...

## Tips

* This project is currently in WIP (Work In Progress), it may have some undiscovered problems.
* If you add multiple DNS servers
  * if the connection fails or there is no response packet, he will try to use the next server.
* `C.getaddrinfo` is incompatible with green threads, It may cause your program to [pause](#related).
  * `C.getaddrinfo` is too bad, you should not use it in green thread.
  * In addition, (libuv `uv_getaddrinfo`, libevent `evdns_getaddrinfo`) is too complicated, you may encounter many problems.
* Why is its name `Durian.cr`, it's just random, six-word English words.
* `Travis-CI` appears to be malfunctioning and this repository cannot be detected.

## Next

* [ ] Support response packet `to_io` operation.
* [ ] More exception handling.
* [ ] Support DNS server features.
* [ ] Better performance, Better DNS cache.

## Using

* Client | Http - Testing DNS resolution for IP availability

```crystal
require "durian"

servers = [] of Tuple(Socket::IPAddress, Durian::Protocol)
servers << Tuple.new Socket::IPAddress.new("8.8.8.8", 53_i32), Durian::Protocol::UDP
servers << Tuple.new Socket::IPAddress.new("1.1.1.1", 53_i32), Durian::Protocol::UDP

buffer = uninitialized UInt8[4096_i32]

resolver = Durian::Resolver.new servers
resolver.ip_cache = Durian::Resolver::Cache::IPAddress.new

begin
  socket = Durian::TCPSocket.new "www.example.com", 80_i32, resolver, 5_i32
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

puts [length, String.new buffer.to_slice[0_i32, length]]
```

* Client | Query - A similar [react](https://reactphp.org/dns/) usage

```crystal
require "durian"

servers = [] of Tuple(Socket::IPAddress, Durian::Protocol)
servers << Tuple.new Socket::IPAddress.new("8.8.8.8", 53_i32), Durian::Protocol::UDP
servers << Tuple.new Socket::IPAddress.new("1.1.1.1", 53_i32), Durian::Protocol::UDP

resolver = Durian::Resolver.new servers
resolver.cache = Durian::Resolver::Cache.new

resolver.resolve "google.com", [Durian::Record::ResourceFlag::A, Durian::Record::ResourceFlag::AAAA] do |response|
  puts [:Google, Time.utc, response]
end

resolver.resolve "twitter.com", Durian::Record::ResourceFlag::SOA do |response|
  puts [:Twitter, Time.utc, response]
end

resolver.resolve "facebook.com", [Durian::Record::ResourceFlag::A, Durian::Record::ResourceFlag::AAAA] do |response|
  puts [:FaceBook, Time.utc, response]
end

resolver.resolve "twitter.com", Durian::Record::ResourceFlag::SOA do |response|
  puts [:Twitter, Time.utc, response]
end

resolver.run
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

* [\_Icon::wanicon/fruits](https://www.flaticon.com/packs/fruits-and-vegetables-48)

## Contributors

|Name|Creator|Maintainer|Contributor|
|:---:|:---:|:---:|:---:|
|**[636f7374](https://github.com/636f7374)**|√|√||
|**[rdp](https://github.com/rdp)**|||√|
|**[teknomunk](https://github.com/teknomunk)**|||√|

## License

* MIT License
