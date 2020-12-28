struct Durian::Record
  struct A < Durian::Record
    property ipv4Address : Socket::IPAddress?

    def initialize(@ipv4Address : Socket::IPAddress? = nil, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::A
    end

    {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    resource_record = new
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    resource_record.ipv4Address = decode_{{name.id}}_ipv4_address io, buffer, data_length
    resource_record
  end

  def self.decode_{{name.id}}_ipv4_address(io : IO,  buffer : IO, length : Int)
    return if length != 4_i32

    temporary = Durian.limit_length_buffer io, length
    IO.copy temporary, buffer rescue nil
    temporary.rewind
    return if temporary.size != length

    Socket::IPAddress.ipv4_from_io io: temporary, addrlen: length rescue nil
  end
  {% end %}
  end
end
