class Durian::TCPSocket < TCPSocket
  def initialize(host : String, port : Int32, resolver : Durian::Resolver, connect_timeout : Int | Float? = nil,
                 retry : Bool = true, retry_timeout : Int | Float = 1_i32,
                 retry_ipv4 : Int | Float = 2_i32, retry_ipv6 : Int | Float = 2_i32)
    method, list = Durian::Resolver.getaddrinfo host, port, resolver
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

  def self.try_connect_ip_address(list : Array(Socket::IPAddress), retry_timeout : Int | Float = 1_i32,
                                  maximum_retry_ipv4 : Int | Float = 4_i32,
                                  maximum_retry_ipv6 : Int | Float = 4_i32) : Socket::IPAddress?
    timeout = retry_timeout / list.size
    timeout = 1_i32 if timeout < 1_i32

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

      socket = ::TCPSocket.new address, timeout, timeout rescue nil
      next unless socket

      if socket
        socket.close
        break address
      end
    end
  end
end
