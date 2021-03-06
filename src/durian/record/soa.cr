struct Durian::Record
  struct SOA < Durian::Record
    property primaryNameServer : String
    property authorityMailBox : String
    property serialNumber : UInt32
    property refreshInterval : UInt32
    property retryInterval : UInt32
    property expireLimit : UInt32
    property minimiumTimeToLive : UInt32

    def initialize(@primaryNameServer : String = String.new, @authorityMailBox : String = String.new,
                   @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::SOA
      @authorityMailBox = String.new
      @serialNumber = 0_u32
      @refreshInterval = 0_u32
      @retryInterval = 0_u32
      @expireLimit = 0_u32
      @minimiumTimeToLive = 0_u32
    end

    {% for name in ["authority", "answer", "additional"] %}
    def self.{{name.id}}_from_io?(protocol : Protocol, io : IO, buffer : IO)
      resource_record = new
      data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      buffer.write_bytes data_length, IO::ByteFormat::BigEndian

      data_buffer = Durian.limit_length_buffer io, data_length

      resource_record.primaryNameServer = Durian.parse_chunk_address protocol, data_buffer, buffer
      resource_record.authorityMailBox = Durian.parse_chunk_address protocol, data_buffer, buffer

      resource_record.serialNumber = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
      resource_record.refreshInterval = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
      resource_record.retryInterval = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
      resource_record.expireLimit = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
      resource_record.minimiumTimeToLive = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian

      buffer.write_bytes resource_record.serialNumber
      buffer.write_bytes resource_record.refreshInterval
      buffer.write_bytes resource_record.retryInterval
      buffer.write_bytes resource_record.expireLimit
      buffer.write_bytes resource_record.minimiumTimeToLive

      resource_record
    end
    {% end %}
  end
end
