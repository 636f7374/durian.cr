module Durian::Network
  def self.create(server : Durian::Resolver::Server, timeout : Option::TimeOut)
    read_timeout = timeout.read.seconds
    write_timeout = timeout.write.seconds
    connect_timeout = timeout.connect.seconds

    create server.ipAddress, server.protocol, server.tls,
      read_timeout, write_timeout, connect_timeout
  end

  def self.create(address : Socket::IPAddress, protocol : Protocol, tls : Durian::Resolver::Server::TransportLayerSecurity? = nil,
                  read_timeout : Time::Span = 5_i32.seconds, write_timeout : Time::Span = 5_i32.seconds,
                  connect_timeout : Time::Span = 5_i32.seconds)
    case protocol
    when .tcp?
      socket = TCPSocket.new address, connect_timeout: connect_timeout
      socket.read_timeout = read_timeout
      socket.write_timeout = write_timeout

      socket
    when .tls?
      socket = TCPSocket.new address, connect_timeout: connect_timeout
      socket.read_timeout = read_timeout
      socket.write_timeout = write_timeout

      openssl_context = OpenSSL::SSL::Context::Client.new

      begin
        ssl_socket = OpenSSL::SSL::Socket::Client.new socket, context: openssl_context, sync_close: true, hostname: tls.try &.hostname
        ssl_socket.sync = true
      rescue ex
        return socket.close
      end

      ssl_socket
    else
      socket = UDPSocket.new family: address.family
      socket.read_timeout = read_timeout
      socket.write_timeout = write_timeout
      socket.connect address, connect_timeout: connect_timeout

      socket
    end
  end
end
