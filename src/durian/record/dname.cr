class Durian::Record
  class DNAME < Durian::Record
    property delegationName : String

    def initialize(@delegationName : String = String.new, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::DNAME
    end

    {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(resource_record : DNAME, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    resource_record.delegationName = DNAME.address_from_io? io, data_length, buffer, maximum_length
  end
  {% end %}

    def self.address_from_io?(io : IO, length : Int, buffer : IO, maximum_length : Int32 = 512_i32)
      Durian.parse_strict_length_address io, length, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
    end

    def self.address_from_io?(io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
      Durian.parse_chunk_address io, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
    end
  end
end
