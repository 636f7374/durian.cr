class Durian::Record
  class A < Durian::Record
    property ipv4Address : String

    def initialize(@ipv4Address : String = String.new, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::A
    end

    {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(resource_record : A, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    resource_record.ipv4Address = decode_{{name.id}}_ipv4_address io, buffer, data_length
  end

  def self.decode_{{name.id}}_ipv4_address(io : IO,  buffer : IO, length : Int)
    return String.new if length != 4_i32

    temporary = Durian.limit_length_buffer io, length
    IO.copy temporary, buffer rescue nil
    temporary.rewind
    return String.new if temporary.size != length

    decode = Durian.decode_{{name.id}}_ipv4_address temporary, length
    temporary.close

    decode
  end
  {% end %}
  end
end
