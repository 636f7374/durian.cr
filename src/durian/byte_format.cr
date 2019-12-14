module Durian::ByteFormat
  def self.extract_uint16_bits(io, buffer : IO) : StaticArray
    bits_buffer = uninitialized UInt8[16_i32]

    begin
      flags = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    rescue ex
      raise PacketTypeError.new ex.message
    end

    buffer.write_bytes flags, IO::ByteFormat::BigEndian
    split = ("%016b" % flags).split String.new

    split.each_with_index do |bit, id|
      break if id > 16_i32
      break unless _bit = bit.to_u8?

      bits_buffer[id] = _bit
    end

    bits_buffer
  end

  def self.parse_four_bit_integer(io : IO) : Int32
    return 0_i32 unless _one_ = io.read_byte
    return 0_i32 unless _two_ = io.read_byte
    return 0_i32 unless three = io.read_byte
    return 0_i32 unless _four = io.read_byte

    return 0_i32 if _one_ > 1_i32 || _two_ > 1_i32
    return 0_i32 if three > 1_i32 || _four > 1_i32

    String.build do |_io|
      _io << _one_ << _two_ << three << _four
    end.to_i32? || 0_i32
  end
end
