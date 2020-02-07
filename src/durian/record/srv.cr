class Durian::Record::SRV < Durian::Record
  property priority : UInt16
  property weight : UInt16
  property port : UInt16
  property target : String

  def initialize(@target : String = String.new, @cls : Cls = Cls::IN, @ttl : UInt32 = 0_u32, @from : String? = nil)
    @flag = RecordFlag::SRV
    @priority = 0_u16
    @weight = 0_u16
    @port = 0_u16
  end

  {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(resource_record : SRV, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    data_buffer = Durian.limit_length_buffer io, data_length
    IO.copy data_buffer, buffer ensure data_buffer.rewind

    resource_record.priority = data_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian
    resource_record.weight = data_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian
    resource_record.port = data_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian

    resource_record.target = Durian.decode_address data_buffer, buffer
  end
  {% end %}
end
