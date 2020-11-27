require "../src/durian.cr"

buffer = uninitialized UInt8[4096_i32]
request = Durian::Packet.new Durian::Protocol::UDP, Durian::Packet::QRFlag::Query
request.add_query "www.example.com", Durian::RecordFlag::A

_request = IO::Memory.new request.to_slice
STDOUT.puts [:Request, Durian::Packet.from_io Durian::Protocol::UDP, _request]

udp_socket = UDPSocket.new
udp_socket.connect Socket::IPAddress.new "8.8.8.8", 53_i32
udp_socket.send _request.to_slice
length, ip_address = udp_socket.receive buffer.to_slice

_response = IO::Memory.new buffer.to_slice[0_i32, length]
STDOUT.puts [:Response, Durian::Packet.from_io Durian::Protocol::UDP, _response]
