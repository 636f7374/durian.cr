struct Durian::Record
  struct MX < Durian::Record
    property mailExchange : String
    property preference : UInt16

    def initialize(@mailExchange : String = String.new, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::MX
      @preference = 0_u32
    end

    {% for name in ["authority", "answer", "additional"] %}
    def self.{{name.id}}_from_io?(protocol, io : IO, buffer : IO)
      resource_record = new
      data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      buffer.write_bytes data_length, IO::ByteFormat::BigEndian

      data_buffer = Durian.limit_length_buffer io, data_length

      resource_record.preference = data_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian
      buffer.write_bytes resource_record.preference

      resource_record.mailExchange = Durian.parse_chunk_address protocol, data_buffer, buffer
      resource_record
    end
    {% end %}
  end
end
