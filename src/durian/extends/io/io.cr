abstract class IO
  def read_network_short : UInt16
    first_byte = read_byte ensure _last_byte = read_byte
    raise IO::Error.new "Expecting two bytes" unless first_byte
    raise IO::Error.new "Expecting two bytes" unless _last_byte

    first_byte.to_u16 << 8_i32 | _last_byte
  end

  def read_network_long : UInt32
    __one_byte = read_byte ensure __two_byte = read_byte
    three_byte = read_byte ensure _four_byte = read_byte

    raise IO::Error.new "Expecting four bytes" unless __one_byte
    raise IO::Error.new "Expecting four bytes" unless __two_byte
    raise IO::Error.new "Expecting four bytes" unless three_byte
    raise IO::Error.new "Expecting four bytes" unless _four_byte

    __one_byte.to_u32 << 24_i32 |
      __two_byte.to_u32 << 16_i32 |
      three_byte.to_u32 << 8_i32 | _four_byte
  end

  def write_network_long(long : Int) : Nil
    write_byte ((long >> 24_i32) & 0xFF).to_u8
    write_byte ((long >> 16_i32) & 0xFF).to_u8
    write_byte ((long >> 8_i32) & 0xFF).to_u8
    write_byte (long & 0xFF).to_u8
  end

  def write_network_short(short : Int) : Nil
    write_byte ((short >> 8_i32) & 0xFF).to_u8
    write_byte (short & 0xFF).to_u8
  end
end
