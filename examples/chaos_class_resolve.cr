# Query local bind server version using CH class, TXT record

require "../src/durian.cr"

buffer = uninitialized UInt8[4096_i32]

request = Durian::Packet::Request.new

request.queries << Durian::Section::Question.new Durian::RecordFlag::TXT, "version.bind", Durian::Cls::CH

_request = IO::Memory.new request.to_slice
puts [:Request, Durian::Packet::Request.from_io _request]

udp_socket = UDPSocket.new
udp_socket.connect Socket::IPAddress.new "127.0.0.1", 53_i32
udp_socket.send _request.to_slice
length, ip_address = udp_socket.receive buffer.to_slice

_response = IO::Memory.new buffer.to_slice[0_i32, length]
puts [:Response, Durian::Packet::Response.from_io _response]
