module Durian::Field
  struct Question
    property flag : RecordFlag
    property query : String
    property cls : Cls

    def initialize(@flag : RecordFlag = RecordFlag::ANY, @query : String = String.new, @cls : Cls = Cls::Internet)
    end

    def encode(io : IO)
      encode flag, io
    end

    def encode(flag : RecordFlag, io : IO)
      return unless _query = query
      Durian.encode_chunk_ipv4_address _query, io

      io.write_bytes flag.to_u16, IO::ByteFormat::BigEndian
      io.write_bytes cls.to_u16, IO::ByteFormat::BigEndian
    end

    def self.encode(flag : RecordFlag, query : String, io : IO, cls : Cls = Cls::Internet)
      question = new flag, query, cls
      question.encode io
    end

    def self.decode(protocol : Protocol, io : IO, buffer : IO)
      query = Durian.parse_chunk_address protocol, io, buffer

      flag = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      _cls = io.read_bytes UInt16, IO::ByteFormat::BigEndian

      question = new RecordFlag.new flag
      question.query = query
      question.cls = Cls.new _cls

      buffer.write_bytes flag, IO::ByteFormat::BigEndian
      buffer.write_bytes _cls, IO::ByteFormat::BigEndian

      question
    end
  end
end
