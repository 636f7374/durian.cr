class Durian::Record
  class CNAME < Durian::Record
    property canonicalName : String

    def initialize(@canonicalName : String = String.new, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::CNAME
    end

    {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(protocol : Protocol, resource_record : CNAME, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    resource_record.canonicalName = CNAME.address_from_io? protocol, io, data_length, buffer, maximum_length
  end
  {% end %}

    def self.address_from_io?(protocol : Protocol, io : IO, length : Int, buffer : IO, maximum_length : Int32 = 512_i32)
      Durian.parse_strict_length_address protocol, io, length, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
    end

    def self.address_from_io?(protocol : Protocol, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
      Durian.parse_chunk_address protocol, io, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
    end
  end
end
