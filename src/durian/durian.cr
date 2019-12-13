module Durian
  RecordType = %w(A AAAA NS PTR CNAME SOA TXT MX)

  enum Protocol
    UDP
    TCP
  end

  class MalformedPacket < Exception
  end

  class UnknownFlag < Exception
  end

  class UnknownSection < Exception
  end

  class NilAddress < Exception
  end

  class PacketTypeError < Exception
  end

  def self.parse_bit_flags(io, buffer : IO)
    flags_buffer = uninitialized UInt8[16_i32]
    slice_buffer = flags_buffer.to_slice

    flags = io.read_network_short rescue nil
    raise PacketTypeError.new unless flags

    buffer.write_network_short flags
    split = ("%016b" % flags).split String.new

    temporary = IO::Memory.new

    split.each_with_index do |bit, id|
      next unless _bit = bit.to_u8?

      if _bit > 1_i32
        temporary.close
        raise PacketTypeError.new
      end

      temporary.write Bytes[_bit] if id < 16_i32
    end

    temporary.rewind
    temporary
  end

  def self.parse_four_bit_integer(io : IO)
    return 0_i32 unless _one_ = io.read_byte
    return 0_i32 unless _two_ = io.read_byte
    return 0_i32 unless three = io.read_byte
    return 0_i32 unless _four = io.read_byte

    return 0_i32 if _one_ > 1_i32 || _two_ > 1_i32
    return 0_i32 if three > 1_i32 || _four > 1_i32

    String.build do |_io|
      _io << _one_ << _two_ << three << _four
    end.to_i? || 0_i32
  end

  def limit_length_buffer(io : IO) : IO::Memory
    next_length = uninitialized UInt8[1_i32]
    length = io.read next_length.to_slice
    return IO::Memory.new if 1_i32 != length

    limit_length_buffer io, next_length.first
  end

  def self.limit_length_buffer(io : IO, length : Int)
    begin
      limit_length_buffer! io, length
    rescue ex
      IO::Memory.new
    end
  end

  def self.limit_length_buffer!(io : IO, length : Int)
    temporary = IO::Memory.new

    begin
      IO.copy io, temporary, length
    rescue ex
      temporary.close
      raise ex
    end

    temporary.rewind
    temporary
  end

  def self.encode_chunk_ipv4_address(address, io : IO)
    return io.write_byte 0_u8 unless address
    return io.write_byte 0_u8 if address.empty?

    parts = address.split "."
    parts.pop if parts.last.empty?

    parts.map do |part|
      io.write_bytes part.size.to_u8
      io << part
    end

    io.write_byte 0_u8
  end

  {% for name in ["authority", "answer", "additional"] %}
  def self.decode_{{name.id}}_ipv4_address(io : IO, length : Int)
    return String.new if length != 4_i32
    buffer = limit_length_buffer io, length
    ipv4_address = [] of String

    loop do
      part = buffer.read_byte rescue nil
      break buffer.close unless part
      ipv4_address << part.to_s << "."
    end

    ipv4_address.pop if "." == ipv4_address.last

    buffer.close
    ipv4_address.join
  end

  def self.decode_{{name.id}}_ipv6_address(io : IO, length : Int)
    return String.new if length != 16_i32
    buffer = limit_length_buffer io, length
    ipv6_address = [] of String

    loop do
      first_byte = buffer.read_byte rescue nil
      _last_byte = buffer.read_byte rescue nil

      break unless first_byte
      break unless _last_byte

      first_hex = ("%02x" % first_byte).split String.new
      _last_hex = ("%02x" % _last_byte).split String.new

      case {first_hex.first, first_hex.last, _last_hex.first, _last_hex.last}
      when {"0", "0", "0", "0"}
        colon = ipv6_address.last == ":" && ipv6_address[-2_i32]? == ":"
        ipv6_address << ":" unless colon
      when {"0", "0", "0", _last_hex.last}
        ipv6_address << _last_hex.last << ":"
      when {"0", "0", _last_hex.first, _last_hex.last}
        ipv6_address << _last_hex.first 
        ipv6_address << _last_hex.last << ":"
      when {"0", first_hex.last, _last_hex.first, _last_hex.last}
        ipv6_address << first_hex.last << _last_hex.first 
        ipv6_address << _last_hex.last << ":"
      else
        ipv6_address << first_hex.first << first_hex.last 
        ipv6_address << _last_hex.first << _last_hex.last << ":"
      end
    end

    ipv6_address.pop if "::" == ipv6_address.last || ":" == ipv6_address.last

    buffer.close
    ipv6_address.join
  end
  {% end %}

  def self.decode_address_by_pointer(buffer : IO, offset : Int, recursive_depth : Int32 = 0_i32, maximum_length : Int32 = 512_i32, maximum_recursive : Int32 = 64_i32)
    return String.new if offset.zero?
    return String.new if offset > buffer.size

    before_buffer_pos = buffer.pos
    buffer.pos = offset
    decode = decode_address buffer, nil, recursive_depth, maximum_length, maximum_recursive
    buffer.pos = before_buffer_pos

    decode
  end

  def self.decode_address_by_pointer(io : IO, buffer : IO, recursive_depth : Int32 = 0_i32, maximum_length : Int32 = 512_i32, maximum_recursive : Int32 = 64_i32)
    limiter = uninitialized UInt8[1_i32]
    length = io.read limiter.to_slice

    return String.new if length.zero?
    return String.new if limiter.first.zero?

    if limiter.first > buffer.size
      return String.new
    end

    decode_address_by_pointer buffer, limiter.first, recursive_depth, maximum_length, maximum_recursive
  end

  def self.decode_address(io : IO, buffer : IO?, recursive_depth : Int32 = 0_i32, maximum_length : Int32 = 512_i32, maximum_recursive : Int32 = 64_i32)
    limiter = uninitialized UInt8[1_i32]
    temporary = IO::Memory.new

    loop do
      break if recursive_depth == maximum_recursive - 1_i32 || maximum_length <= temporary.size

      length = io.read limiter.to_slice
      break if length.zero? || limiter.first.zero?
      buffer = io unless buffer

      if 0b11000000 == limiter.first
        break temporary << decode_address_by_pointer io, buffer,
          recursive_depth + 1_i32, maximum_length, maximum_recursive
      end

      IO.copy io, temporary, limiter.first
      temporary << "."
    end

    _address = String.new temporary.to_slice
    _address = _address[0_i32..-2_i32] if _address.ends_with?('.') && 2_i32 <= _address.size

    temporary.close
    _address
  end

  def self.parse_strict_length_address(io : IO, length : Int, buffer : IO, recursive_depth : Int32 = 0_i32, maximum_length : Int32 = 512_i32, maximum_recursive : Int32 = 64_i32)
    return String.new if length > maximum_length

    temporary = limit_length_buffer io, length
    IO.copy temporary, buffer rescue nil
    temporary.rewind

    if temporary.size != length
      temporary.close
      return String.new
    end

    decode = decode_address temporary, buffer, recursive_depth, maximum_length, maximum_recursive
    temporary.close

    decode
  end

  def self.parse_chunk_address(io : IO, buffer : IO, recursive_depth : Int32 = 0_i32, maximum_length : Int32 = 512_i32, maximum_recursive : Int32 = 64_i32)
    limiter = uninitialized UInt8[1_i32]
    temporary = IO::Memory.new
    pointer_address_buffer = IO::Memory.new
    end_zero = false

    loop do
      break if maximum_length <= temporary.size

      length = io.read limiter.to_slice
      break unless length
      break if length.zero?
      break end_zero = true if limiter.first.zero?

      if 0b11000000 == limiter.first
        break pointer_address_buffer << decode_address_by_pointer io, buffer
      end

      temporary.write limiter.to_slice
      IO.copy io, temporary, limiter.first
    end

    temporary.rewind
    IO.copy temporary, buffer
    buffer.write Bytes[0_i32] if end_zero
    temporary.rewind

    decode = decode_address temporary, buffer, recursive_depth, maximum_length, maximum_recursive
    pointer_address = pointer_address_buffer.to_slice
    temporary.close ensure pointer_address_buffer.close

    String.build do |io|
      io << decode << String.new pointer_address
    end
  end
end
