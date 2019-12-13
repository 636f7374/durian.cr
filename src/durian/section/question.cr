module Durian::Section
  class Question
    alias ResourceFlag = Record::ResourceFlag
    alias Cls = Record::Cls

    property flag : ResourceFlag
    property query : String
    property cls : Cls

    def initialize(@flag : ResourceFlag = ResourceFlag::ANY, @query : String = String.new, @cls : Cls = Cls::IN)
    end

    def encode(io : IO)
      encode flag, io
    end

    def encode(flag : ResourceFlag, io : IO)
      return unless _query = query

      Durian.encode_chunk_ipv4_address _query, io
      io.write_network_short flag.to_i32
      io.write_network_short cls.to_i32
    end

    def self.encode(flag : ResourceFlag, query : String, io : IO, cls : Cls = Cls::IN)
      question = new flag, query, cls
      question.encode io
    end

    def self.decode(io : IO, buffer : IO)
      query = Durian.parse_chunk_address io, buffer
      flag = ResourceFlag.new io.read_network_short.to_i32
      _cls = Cls.new io.read_network_short.to_i32
      question = new flag, query, _cls

      buffer.write_network_short flag.to_i32
      buffer.write_network_short _cls.to_i32

      question
    end
  end
end
