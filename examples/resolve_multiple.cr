require "../src/durian.cr"

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
