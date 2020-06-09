class Durian::Record
  class AAAA < Durian::Record
    property ipv6Address : String

    def initialize(@ipv6Address : String = String.new, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::AAAA
    end

    {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(resource_record : AAAA, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    resource_record.ipv6Address = decode_{{name.id}}_ipv6_address io, buffer, data_length
  end

  def self.decode_{{name.id}}_ipv6_address(io : IO,  buffer : IO, length : Int)
    return String.new if length != 16_i32

    temporary = Durian.limit_length_buffer io, length
    IO.copy temporary, buffer rescue nil
    temporary.rewind
    return String.new if temporary.size != length

    ip_address = Socket::IPAddress.ipv6_from_io io: temporary, addrlen: length rescue nil
    ip_address.try &.address || String.new
  end
  {% end %}
  end
end
