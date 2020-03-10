class Durian::Record::SOA < Durian::Record
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
  def self.{{name.id}}_from_io?(resource_record : SOA, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    data_buffer = Durian.limit_length_buffer io, data_length
    IO.copy data_buffer, buffer ensure data_buffer.rewind

    resource_record.primaryNameServer = Durian.decode_address data_buffer, buffer
    resource_record.authorityMailBox = Durian.decode_address data_buffer, buffer

    resource_record.serialNumber = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
    resource_record.refreshInterval = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
    resource_record.retryInterval = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
    resource_record.expireLimit = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
    resource_record.minimiumTimeToLive = data_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
  end
  {% end %}
end
