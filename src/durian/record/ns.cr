class Durian::Record::NS < Durian::Record
  property nameServer : String

  def initialize(@nameServer : String = String.new, @cls : Cls = Cls::IN, @ttl : UInt32 = 0_u32, @from : String? = nil)
  end

  {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(resource_record : NS, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_network_short
    buffer.write_network_short data_length

    resource_record.nameServer = address_from_io? io, data_length, buffer, maximum_length
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
