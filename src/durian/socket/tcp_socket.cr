class Durian::TCPSocket < TCPSocket
  alias Cache = Durian::Resolver::Cache::IPAddress

  def initialize(host : String, port : Int32, resolver : Durian::Resolver, connect_timeout : Int32? = nil,
                 retry : Bool = true, retry_timeout : Int32 = 1_i32,
                 retry_ipv4 : Int32 = 2_i32, retry_ipv6 : Int32 = 2_i32)
    Durian::Resolver.getaddrinfo host, port, resolver do |list|
      raise Socket::Error.new "Invalid host address" if list.empty?

      if 1_i32 == list.size || false == retry
        return super list.first, connect_timeout, connect_timeout
      end

      ip_address = TCPSocket.try_connect_ip_address list, retry_timeout, retry_ipv4, retry_ipv6
      raise Socket::Error.new "IP address cannot connect" unless ip_address

      if ip_cache = resolver.ip_cache
        ip_cache.set host, ip_address
      end

      super ip_address, connect_timeout, connect_timeout
    end
  end

  def self.try_connect_ip_address(list : Array(Socket::IPAddress), retry_timeout : Int32 = 1_i32,
                                  maximum_retry_ipv4 : Int32 = 2_i32, maximum_retry_ipv6 : Int32 = 2_i32) : Socket::IPAddress?
    retry_ipv4 = 0_i32
    retry_ipv6 = 0_i32

    list.each do |address|
      break if retry_ipv6 == maximum_retry_ipv6 && retry_ipv4 == maximum_retry_ipv4

      case address.family
      when .inet6?
        next if retry_ipv6 == maximum_retry_ipv6
        retry_ipv6 = retry_ipv6 + 1_i32
      when .inet?
        next if retry_ipv4 == maximum_retry_ipv4
        retry_ipv4 = retry_ipv4 + 1_i32
      end

      socket = ::TCPSocket.new address, retry_timeout, retry_timeout rescue nil
      next unless socket

      if socket
        socket.close
        break address
      end
    end
  end
end
