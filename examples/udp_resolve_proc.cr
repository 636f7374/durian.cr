require "../src/durian.cr"

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
