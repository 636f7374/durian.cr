module Durian::Section
  class Authority
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
      authority = new flag

      _cls = Cls.new io.read_network_short.to_i32
      _ttl = io.read_network_long

      authority.resourceRecord.from = from
      authority.resourceRecord.cls = _cls
      authority.resourceRecord.ttl = _ttl

      buffer.write_network_short flag.to_i32
      buffer.write_network_short _cls.to_i32
      buffer.write_network_long _ttl

      Section.decode_record_authority authority.resourceRecord, io, buffer

      authority
    end
  end
end
