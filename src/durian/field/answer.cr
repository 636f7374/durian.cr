module Durian::Field
  class Answer
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
      from = Durian.decode_resource_pointer protocol, io, buffer
      flag = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      _cls = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      _ttl = io.read_bytes UInt32, IO::ByteFormat::BigEndian

      answer = new RecordFlag.new flag
      answer.resourceRecord.from = from
      answer.resourceRecord.cls = Cls.new _cls
      answer.resourceRecord.ttl = _ttl

      buffer.write_bytes flag, IO::ByteFormat::BigEndian
      buffer.write_bytes _cls, IO::ByteFormat::BigEndian
      buffer.write_bytes _ttl, IO::ByteFormat::BigEndian

      Record.decode_answer protocol, answer.resourceRecord, io, buffer

      answer
    end
  end
end
