module Durian::Section
  class Answer
    alias ResourceFlag = Record::ResourceFlag
    alias Cls = Record::Cls

    property resourceRecord : Record

    def initialize(flag : ResourceFlag = ResourceFlag::ANY)
      @resourceRecord = Section.new_resource_record flag
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

    def self.decode(io : IO, buffer : IO)
      from = Section.decode_resource_pointer io, buffer
      flag = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      _cls = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      _ttl = io.read_bytes UInt32, IO::ByteFormat::BigEndian

      answer = new ResourceFlag.new flag.to_i32
      answer.resourceRecord.from = from
      answer.resourceRecord.cls = Cls.new _cls.to_i32
      answer.resourceRecord.ttl = _ttl

      buffer.write_bytes flag, IO::ByteFormat::BigEndian
      buffer.write_bytes _cls, IO::ByteFormat::BigEndian
      buffer.write_bytes _ttl, IO::ByteFormat::BigEndian

      Section.decode_record_answer answer.resourceRecord, io, buffer

      answer
    end
  end
end
