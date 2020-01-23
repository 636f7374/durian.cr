class Durian::Record::PTR < Durian::Record
  property domainName : String

  def initialize(@domainName : String = String.new, @cls : Cls = Cls::IN, @ttl : UInt32 = 0_u32, @from : String? = nil)
    @flag = RecordFlag::PTR
  end

  {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(resource_record : PTR, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    resource_record.domainName = address_from_io? io, data_length, buffer, maximum_length
  end
  {% end %}

  def self.address_from_io?(io : IO, length : Int, buffer : IO, maximum_length : Int32 = 512_i32)
    Durian.parse_strict_length_address io, length, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
  end

  def self.address_from_io?(io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    Durian.parse_chunk_address io, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
  end

  def address_from_io?(io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    NS.address_from_io? io, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
  end

  def address_from_io?(io : IO, length : Int, buffer : IO, maximum_length : Int32 = 512_i32)
    NS.address_from_io? io, length, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
  end
end
