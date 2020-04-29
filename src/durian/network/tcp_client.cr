class Durian::Network
  class TCPClient < Network
    property address : Socket::IPAddress
    property connectTimeout : Time::Span

    def initialize(@address : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32), @connectTimeout : Time::Span = 5_i32.seconds)
    end

    def socket=(value : TCPSocket)
      @socket = value
    end

    def socket : TCPSocket
      _socket = @socket
      return _socket if _socket

      socket = TCPSocket.new address, connectTimeout, connectTimeout

      socket.read_timeout = read_timeout
      socket.write_timeout = write_timeout

      @socket = socket
    end

    def <<(value : String)
      socket << value
    end

    def send(value : Bytes)
      socket.write value
    end

    def write(value : Bytes)
      socket.write value
    end

    def read(value : Bytes)
      socket.read value
    end

    def receive(value : Bytes)
      Tuple.new socket.read(value), socket.remote_address
    end

    def close
      @socket.try &.close
    end

    def read_timeout=(value : Int32)
      @readTimeout = value.seconds
    end

    def read_timeout=(value : Time::Span)
      @readTimeout = value
    end

    def write_timeout=(value : Int32)
      @writeTimeout = value.seconds
    end

    def write_timeout=(value : Time::Span)
      @writeTimeout = value
    end

    def read_timeout
      @readTimeout || Network.default_read_timeout
    end

    def write_timeout
      @writeTimeout || Network.default_write_timeout
    end
  end
end
