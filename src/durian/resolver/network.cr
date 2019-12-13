class Durian::Resolver
  abstract class Network
    abstract def read_timeout=(value : Int32)
    abstract def read_timeout=(value : Time::Span)
    abstract def write_timeout=(value : Int32)
    abstract def write_timeout=(value : Time::Span)
    abstract def read_timeout
    abstract def write_timeout
    abstract def socket
    abstract def <<(value : String)
    abstract def send(value : Bytes)
    abstract def write(value : Bytes)
    abstract def read(value : Bytes)
    abstract def receive(value : Bytes)
    abstract def close

    def self.default_read_timeout
      2_i32.seconds
    end

    def self.default_write_timeout
      2_i32.seconds
    end

    def self.create_client(server : Tuple(Socket::IPAddress, Protocol), read_timeout : Time::Span = 5_i32.seconds,
                           write_timeout : Time::Span = 5_i32.seconds, connect_timeout : Time::Span = 5_i32.seconds)
      create_client server.first, server.last, read_timeout, write_timeout, connect_timeout
    end

    def self.create_client(server : Socket::IPAddress, protocol : Protocol, read_timeout : Time::Span = 5_i32.seconds,
                           write_timeout : Time::Span = 5_i32.seconds, connect_timeout : Time::Span = 5_i32.seconds)
      case protocol
      when .tcp?
        tcp = TCPClient.new server, connect_timeout
        tcp.read_timeout = read_timeout
        tcp.write_timeout = write_timeout
        tcp.socket

        tcp
      else
        udp = UDPClient.new server
        udp.read_timeout = read_timeout
        udp.write_timeout = write_timeout
        udp.socket

        udp
      end
    end
  end
end

require "./network/*"
