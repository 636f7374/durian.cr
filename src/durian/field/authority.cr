module Durian::Field
  class Authority
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

    def self.decode(io : IO, buffer : IO)
      from = Durian.decode_resource_pointer io, buffer
      flag = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      _cls = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      _ttl = io.read_bytes UInt32, IO::ByteFormat::BigEndian

      authority = new RecordFlag.new flag
      authority.resourceRecord.from = from
      authority.resourceRecord.cls = Cls.new _cls
      authority.resourceRecord.ttl = _ttl

      buffer.write_bytes flag, IO::ByteFormat::BigEndian
      buffer.write_bytes _cls, IO::ByteFormat::BigEndian
      buffer.write_bytes _ttl, IO::ByteFormat::BigEndian

      Record.decode_authority authority.resourceRecord, io, buffer

      authority
    end
  end
end
