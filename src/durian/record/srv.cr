struct Durian::Record
  struct SRV < Durian::Record
    property priority : UInt16
    property weight : UInt16
    property port : UInt16
    property target : String

    def initialize(@target : String = String.new, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::SRV
      @priority = 0_u16
      @weight = 0_u16
      @port = 0_u16
    end

    {% for name in ["authority", "answer", "additional"] %}
    def self.{{name.id}}_from_io?(protocol : Protocol, io : IO, buffer : IO)
      resource_record = new
      data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      buffer.write_bytes data_length, IO::ByteFormat::BigEndian

      data_buffer = Durian.limit_length_buffer io, data_length

      resource_record.priority = data_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian
      resource_record.weight = data_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian
      resource_record.port = data_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian

      buffer.write_bytes resource_record.priority
      buffer.write_bytes resource_record.weight
      buffer.write_bytes resource_record.port

      resource_record.target = Durian.parse_chunk_address protocol, data_buffer, buffer
      resource_record
    end
    {% end %}
  end
end
