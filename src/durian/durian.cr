module Durian
  RecordType = %w(A AAAA NS PTR CNAME SOA TXT MX)

  enum Protocol
    UDP
    TCP
  end

  enum RecordFlag
    # Pseudo Record Types
    ANY  = 255_i32
    AXFR = 252_i32
    IXFR = 251_i32
    OPT  =  41_i32

    # Active Record Types
    A          =     1_i32
    AAAA       =    28_i32
    AFSDB      =    18_i32
    APL        =    42_i32
    CAA        =   257_i32
    CDNSKEY    =    60_i32
    CDS        =    59_i32
    CERT       =    37_i32
    CNAME      =     5_i32
    DHCID      =    49_i32
    DLV        = 32769_i32
    DNAME      =    39_i32
    DNSKEY     =    48_i32
    DS         =    43_i32
    HIP        =    55_i32
    IPSECKEY   =    25_i32
    KX         =    36_i32
    LOC        =    29_i32
    MX         =    15_i32
    NAPTR      =    35_i32
    NS         =     2_i32
    NSEC       =    47_i32
    NSEC3      =    50_i32
    NSEC3PARAM =    51_i32
    OPENPGPKEY =    61_i32
    PTR        =    12_i32
    RRSIG      =    46_i32
    RP         =    17_i32
    SIG        =    24_i32
    SOA        =     6_i32
    SRV        =    33_i32
    SSHFP      =    44_i32
    TA         = 32768_i32
    TKEY       =   249_i32
    TLSA       =    52_i32
    TSIG       =   250_i32
    TXT        =    16_i32
    URI        =   256_i32

    # Obsolete Record Types
    MD       =   3_i32
    MF       =   4_i32
    MAILA    = 254_i32
    MB       =   7_i32
    MG       =   8_i32
    MR       =   9_i32
    MINFO    =  14_i32
    MAILB    = 253_i32
    WKS      =  11_i32
    NB       =  32_i32
    NBSTAT   =  33_i32
    NULL     =  10_i32
    A6       =  38_i32
    NXT      =  30_i32
    KEY      =  25_i32
    HINFO    =  13_i32
    X25      =  19_i32
    ISDN     =  20_i32
    RT       =  21_i32
    NSAP     =  22_i32
    NSAP_PTR =  23_i32
    PX       =  26_i32
    EID      =  31_i32
    NIMLOC   =  32_i32
    ATMA     =  34_i32
    SINK     =  40_i32
    GPOS     =  27_i32
    UINFO    = 100_i32
    UID      = 101_i32
    GID      = 102_i32
    UNSPEC   = 103_i32
    SPF      =  99_i32
  end

  enum Cls
    IN = 1_i32
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

  def limit_length_buffer(io : IO) : IO::Memory
    next_length = uninitialized UInt8[1_i32]
    length = io.read next_length.to_slice
    return IO::Memory.new if 1_i32 != length

    limit_length_buffer io, next_length.first
  end

  def self.limit_length_buffer(io : IO, length : Int)
    limit_length_buffer! io, length rescue IO::Memory.new
  end

  def self.limit_length_buffer!(io : IO, length : Int)
    temporary = IO::Memory.new
    IO.copy io, temporary, length rescue nil

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
