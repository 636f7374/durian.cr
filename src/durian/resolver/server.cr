class Durian::Resolver
  class Server
    property ipAddress : Socket::IPAddress
    property protocol : Protocol
    property tls : TransportLayerSecurity?

    def initialize(@ipAddress : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32),
                   @protocol : Protocol = Protocol::UDP, @tls : TransportLayerSecurity? = nil)
    end

    class TransportLayerSecurity
      property hostname : String?

      def initialize(@hostname : String? = nil)
      end
    end
  end
end
