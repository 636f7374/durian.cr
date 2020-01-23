class Durian::Record::MX < Durian::Record
  property mailExchange : String
  property preference : UInt16

  def initialize(@mailExchange : String = String.new, @cls : Cls = Cls::IN, @ttl : UInt32 = 0_u32, @from : String? = nil)
    @flag = RecordFlag::MX
    @preference = 0_u32
  end

  {% for name in ["authority", "answer", "additional"] %}
  def self.{{name.id}}_from_io?(resource_record : MX, io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    data_length = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    buffer.write_bytes data_length, IO::ByteFormat::BigEndian

    data_buffer = Durian.limit_length_buffer io, data_length

    begin
      IO.copy data_buffer, buffer ensure data_buffer.rewind

      resource_record.preference = data_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian
      resource_record.mailExchange = Durian.decode_address data_buffer, buffer
    rescue ex
      data_buffer.close ensure raise ex
    end

    data_buffer.close
  end
  {% end %}

  def self.address_from_io?(io : IO, length : Int, buffer : IO, maximum_length : Int32 = 512_i32)
    Durian.parse_strict_length_address io, length, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
  end

  def self.address_from_io?(io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    Durian.parse_chunk_address io, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
  end

  def address_from_io?(io : IO, buffer : IO, maximum_length : Int32 = 512_i32)
    MX.address_from_io? io, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
  end

  def address_from_io?(io : IO, length : Int, buffer : IO, maximum_length : Int32 = 512_i32)
    MX.address_from_io? io, length, buffer, recursive_depth: 0_i32, maximum_length: maximum_length
  end
end
