class Durian::TCPSocket < TCPSocket
  def self.connect(host : String, port : Int32, resolver : Durian::Resolver, connect_timeout : Int | Float? = nil)
    Resolver.get_tcp_socket! host, port, durian, connect_timeout
  end

  def self.try_connect_ip_address(list : Array(Socket::IPAddress), retry : Option::Retry?) : Socket::IPAddress?
    return unless choice = choice_ip_address list, retry

    socket, address = choice
    socket.close
    address
  end

  def self.choice_ip_address(list : Array(Socket::IPAddress), retry : Option::Retry?) : Tuple(::TCPSocket, Socket::IPAddress)?
    retry_timeout, maximum_retry_ipv6, maximum_retry_ipv4 = 1_i32, 2_i32, 2_i32

    if _retry = retry
      retry_timeout = retry.timeout
      maximum_retry_ipv6 = retry.maximumIpv6
      maximum_retry_ipv4 = retry.maximumIpv4
    end

    timeout = retry_timeout / list.size
    timeout = 1_i32 if timeout < 1_i32

    retry_ipv4 = 0_i32
    retry_ipv6 = 0_i32

    list.each do |address|
      break if retry_ipv6 == maximum_retry_ipv6 && retry_ipv4 == maximum_retry_ipv4

      case address.family
      when .inet6?
        next if retry_ipv6 == maximum_retry_ipv6
        retry_ipv6 += 1_i32
      when .inet?
        next if retry_ipv4 == maximum_retry_ipv4
        retry_ipv4 += 1_i32
      end

      socket = ::TCPSocket.new address, timeout, timeout rescue nil
      next unless socket

      break Tuple.new socket, address
    end
  end
end
