module Durian::Section
  class Additional
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
      flag = ResourceFlag.new io.read_network_short.to_i32
      additional = new flag

      _cls = Cls.new io.read_network_short.to_i32
      _ttl = io.read_network_long

      additional.resourceRecord.from = from
      additional.resourceRecord.cls = _cls
      additional.resourceRecord.ttl = _ttl

      buffer.write_network_short flag.to_i32
      buffer.write_network_short _cls.to_i32
      buffer.write_network_long _ttl

      Section.decode_record_additional additional.resourceRecord, io, buffer

      additional
    end
  end
end
