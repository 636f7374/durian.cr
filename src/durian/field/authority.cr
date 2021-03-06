module Durian::Field
  struct Authority
    property resourceRecord : Record

    def initialize(flag : RecordFlag = RecordFlag::ANY)
      @resourceRecord = Record.new flag
    end

    def from
      @resourceRecord.from
    end

    def cls
      @resourceRecord.cls
    end

    def ttl
      @resourceRecord.ttl
    end

    def flag
      @resourceRecord.flag
    end

    def self.decode(protocol : Protocol, io : IO, buffer : IO)
      from = Durian.decode_by_resource_pointer protocol, io, buffer
      flag = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      _cls = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      _ttl = io.read_bytes UInt32, IO::ByteFormat::BigEndian

      authority = new RecordFlag.new flag

      buffer.write_bytes flag, IO::ByteFormat::BigEndian
      buffer.write_bytes _cls, IO::ByteFormat::BigEndian
      buffer.write_bytes _ttl, IO::ByteFormat::BigEndian

      raise "Decode Record Authority failed" unless resource_record = Record.decode_authority protocol, authority.flag, io, buffer
      resource_record.from = from
      resource_record.cls = Cls.new _cls
      resource_record.ttl = _ttl
      authority.resourceRecord = resource_record

      authority
    end
  end
end
