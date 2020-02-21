module Durian
  RecordType = %w(A AAAA NS PTR CNAME SOA TXT MX DNAME SRV)

  enum Protocol
    UDP
    TCP
  end

  enum Fetch
    Local
    Cache
    Remote
  end

  enum RecordFlag : UInt16
    # Pseudo Record Types
    ANY  = 255_u16
    AXFR = 252_u16
    IXFR = 251_u16
    OPT  =  41_u16

    # Active Record Types
    A          =     1_u16
    AAAA       =    28_u16
    AFSDB      =    18_u16
    APL        =    42_u16
    CAA        =   257_u16
    CDNSKEY    =    60_u16
    CDS        =    59_u16
    CERT       =    37_u16
    CNAME      =     5_u16
    DHCID      =    49_u16
    DLV        = 32769_u16
    DNAME      =    39_u16
    DNSKEY     =    48_u16
    DS         =    43_u16
    HIP        =    55_u16
    IPSECKEY   =    25_u16
    KX         =    36_u16
    LOC        =    29_u16
    MX         =    15_u16
    NAPTR      =    35_u16
    NS         =     2_u16
    NSEC       =    47_u16
    NSEC3      =    50_u16
    NSEC3PARAM =    51_u16
    OPENPGPKEY =    61_u16
    PTR        =    12_u16
    RRSIG      =    46_u16
    RP         =    17_u16
    SIG        =    24_u16
    SOA        =     6_u16
    SRV        =    33_u16
    SSHFP      =    44_u16
    TA         = 32768_u16
    TKEY       =   249_u16
    TLSA       =    52_u16
    TSIG       =   250_u16
    TXT        =    16_u16
    URI        =   256_u16

    # Obsolete Record Types
    MD       =   3_u16
    MF       =   4_u16
    MAILA    = 254_u16
    MB       =   7_u16
    MG       =   8_u16
    MR       =   9_u16
    MINFO    =  14_u16
    MAILB    = 253_u16
    WKS      =  11_u16
    NB       =  32_u16
    NBSTAT   =  33_u16
    NULL     =  10_u16
    A6       =  38_u16
    NXT      =  30_u16
    KEY      =  25_u16
    HINFO    =  13_u16
    X25      =  19_u16
    ISDN     =  20_u16
    RT       =  21_u16
    NSAP     =  22_u16
    NSAP_PTR =  23_u16
    PX       =  26_u16
    EID      =  31_u16
    NIMLOC   =  32_u16
    ATMA     =  34_u16
    SINK     =  40_u16
    GPOS     =  27_u16
    UINFO    = 100_u16
    UID      = 101_u16
    GID      = 102_u16
    UNSPEC   = 103_u16
    SPF      =  99_u16
  end

  enum Cls : UInt8
    IN = 1_u8
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
    chunk_length = uninitialized UInt8[1_i32]
    length = io.read chunk_length.to_slice
    return IO::Memory.new 0_i32 if 1_i32 != length

    limit_length_buffer io, chunk_length.first
  end

  def self.limit_length_buffer(io : IO, length : Int)
    limit_length_buffer! io, length rescue IO::Memory.new 0_i32
  end

  def self.limit_length_buffer!(io : IO, length : Int)
    temporary = IO::Memory.new
    IO.copy io, temporary, length rescue nil

    temporary.rewind
    temporary
  end

  def self.encode_chunk_ipv4_address(ip_address, io : IO)
    return io.write_byte 0_u8 unless ip_address
    return io.write_byte 0_u8 if ip_address.empty?

    parts = ip_address.split "."
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
        next if ipv6_address.empty?

        colon = ":" == ipv6_address.last && ":" == ipv6_address[-2_i32]?
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

    return "::" if ipv6_address.empty?

    address = ipv6_address.join
    return String.build { |io| io << "::" << address } if address.to_i?

    address
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
    chunk_length = uninitialized UInt8[1_i32]
    length = io.read chunk_length.to_slice

    return String.new if length.zero?
    return String.new if chunk_length.first.zero?

    if chunk_length.first > buffer.size
      return String.new
    end

    decode_address_by_pointer buffer, chunk_length.first, recursive_depth, maximum_length, maximum_recursive
  end

  def self.decode_address(io : IO, buffer : IO?, recursive_depth : Int32 = 0_i32, maximum_length : Int32 = 512_i32, maximum_recursive : Int32 = 64_i32)
    chunk_length = uninitialized UInt8[1_i32]
    temporary = IO::Memory.new

    loop do
      break if recursive_depth == maximum_recursive - 1_i32 || maximum_length <= temporary.size

      length = io.read chunk_length.to_slice
      break if length.zero? || chunk_length.first.zero?
      buffer = io unless buffer

      if 0b11000000 == chunk_length.first
        break temporary << decode_address_by_pointer io, buffer, recursive_depth + 1_i32, maximum_length, maximum_recursive
      end

      IO.copy io, temporary, chunk_length.first
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
    chunk_length = uninitialized UInt8[1_i32]
    temporary = IO::Memory.new
    pointer_address_buffer = IO::Memory.new
    end_zero = false

    loop do
      break if maximum_length <= temporary.size
      break unless length = io.read chunk_length.to_slice
      break if length.zero?
      break end_zero = true if chunk_length.first.zero?

      if 0b11000000 == chunk_length.first
        break pointer_address_buffer << decode_address_by_pointer io, buffer
      end

      temporary.write chunk_length.to_slice
      IO.copy io, temporary, chunk_length.first
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
