class Durian::Record
  class TXT < Durian::Record
    property txt : String

    def initialize(@txt : String = String.new, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::TXT
    end

    {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(resource_record : TXT, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    raise MalformedPacket.new unless txt_length = io.read_byte

    buffer.write Bytes[txt_length]

    data_buffer = IO::Memory.new
    IO.copy io, data_buffer, txt_length

    resource_record.txt = String.new data_buffer.to_slice
    data_buffer.close
  end
  {% end %}
  end
end
