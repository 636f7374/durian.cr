struct Durian::Record
  struct DNAME < Durian::Record
    property delegationName : String

    def initialize(@delegationName : String = String.new, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32, @from : String? = nil)
      @flag = RecordFlag::DNAME
    end

    {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(protocol, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    resource_record = new
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    resource_record.delegationName = DNAME.address_from_io? protocol, io, data_length, buffer, maximum_length
    resource_record
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
