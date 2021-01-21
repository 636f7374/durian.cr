module Durian
  AvailableRecordFlag = ["A", "AAAA", "NS", "PTR", "CNAME", "SOA", "TXT", "MX", "DNAME", "SRV"]

  enum Protocol : UInt8
    UDP = 0_u8
    TCP = 1_u8
    TLS = 2_u8
  end

  enum Fetch : UInt8
    Coffee = 0_u8
    Local  = 1_u8
    Cache  = 2_u8
    Remote = 3_u8
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

  enum Cls : UInt16
    Reserved   = 0_u16 # RFC 6895
    Internet   = 1_u16 # RFC 1035
    Unassigned = 2_u16 # ... ....
    Chaos      = 3_u16 # RFC 2929 | D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981.
    Hesiod     = 4_u16 # ... .... | Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan - Name Service, April 1987.
    #     5 -   253 0x0005-0x00FD Unassigned
    QClassNone = 254_u16 # RFC 2136
    QClassAny  = 255_u16 # RFC 1035
    #   256 - 65279 0x0100-0xFEFF Unassigned
    # 65280 - 65534 0xFF00-0xFFFE Reserved for Private Use [RFC 6895]
    AnotherReserved = 65535_u16 # RFC 6895
  end

  class MalformedPacket < Exception
  end

  class UnknownFlag < Exception
  end

  class UnknownField < Exception
  end

  class BadPacket < Exception
  end

  enum ResourcePointer : UInt8
    BadLength      = 0_u8
    InvalidPointer = 1_u8
    OffsetZero     = 2_u8
    Successed      = 4_u8
  end

  enum ChunkFlag : UInt8
    BadLength        = 0_u8
    IndexOutOfBounds = 1_u8
    ResourcePointer  = 2_u8
    Successed        = 3_u8
  end

  def self.decode_chunk(buffer : IO::Memory) : Tuple(ChunkFlag, Array(String), UInt8)
    chunk_parts = [] of String

    loop do
      chunk_length_buffer = uninitialized UInt8[1_i32]
      read_length = buffer.read chunk_length_buffer.to_slice
      chunk_length = chunk_length_buffer.to_slice[0_i32]

      return Tuple.new ChunkFlag::BadLength, chunk_parts, chunk_length if 1_i32 != read_length
      break if chunk_length.zero?

      if 0b00000011 == (chunk_length >> 6_i32)
        return Tuple.new ChunkFlag::ResourcePointer, chunk_parts, chunk_length
      end

      if chunk_length > buffer.size
        return Tuple.new ChunkFlag::IndexOutOfBounds, chunk_parts, chunk_length
      end

      temporary = IO::Memory.new chunk_length
      copy_length = IO.copy buffer, temporary, chunk_length

      return Tuple.new ChunkFlag::BadLength, chunk_parts, chunk_length if copy_length.zero?

      chunk_parts << String.new temporary.to_slice[0_i32, copy_length]
    end

    Tuple.new ChunkFlag::Successed, chunk_parts, 0_u8
  end

  def self.update_chunk_resource_pointer_position(protocol : Protocol, buffer : IO::Memory, chunk_length : UInt8, question : Bool = false)
    offset_buffer = uninitialized UInt8[1_i32]
    read_length = buffer.read offset_buffer.to_slice
    return ResourcePointer::BadLength if 1_i32 != read_length

    # References: A warm welcome to DNS - https://powerdns.org/hello-dns/basic.md.html
    # In this case, the DNS name of the answer is encoded is 0xc0 0x0c.
    # The c0 part has the two most significant bits set, indicating that the following 6+8 bits are a pointer to somewhere earlier in the message.
    # In this case, this points to position 12 (= 0x0c) within the packet, which is immediately after the DNS header.
    # There we find 'www.ietf.org'.
    # Note: (pointer 6bits + offset 8bits)

    offset = offset_buffer.to_slice[0_i32]
    offset = ((chunk_length - 0b11000000).to_i32 << 8_u8) | offset
    return ResourcePointer::OffsetZero if offset.zero?
    return ResourcePointer::BadLength if offset > buffer.size

    before_buffer_pos = buffer.pos
    buffer.pos = offset
    buffer.pos += 2_i32 unless question if protocol.tcp? || protocol.tls?

    ResourcePointer::Successed
  end

  def self.decode_by_resource_pointer(protocol : Protocol, io : IO, buffer : IO::Memory, maximum_depth : Int32 = 65_i32)
    pointer_buffer = uninitialized UInt8[2_i32]
    read_length = io.read pointer_buffer.to_slice
    buffer.write pointer_buffer.to_slice[0_i32, read_length]

    if 2_i32 != read_length
      raise MalformedPacket.new "Expecting two bytes"
    end

    pointer_flag = pointer_buffer.to_slice[0_i32]

    if 0b00000011 != (pointer_flag >> 6_i32)
      raise MalformedPacket.new "Invalid resource pointer"
    end

    offset = pointer_buffer.to_slice[1_i32]
    offset = ((pointer_flag - 0b11000000).to_i32 << 8_u8) | offset
    raise MalformedPacket.new "Expecting one bytes" if offset.zero?
    raise MalformedPacket.new "Offset index out Of bounds" if offset > buffer.size

    depth_decode_by_resource_pointer! protocol, buffer, offset, maximum_depth: maximum_depth
  end

  def self.depth_decode_by_resource_pointer!(protocol : Protocol, buffer : IO::Memory, offset : Int,
                                             question : Bool = false, maximum_depth : Int32 = 65_i32) : String?
    before_buffer_pos = buffer.pos
    buffer.pos = offset
    buffer.pos += 2_i32 unless question if protocol.tcp? || protocol.tls?

    chunk_list = [] of Array(String)
    depth = maximum_depth

    while !(maximum_depth -= 1_i32).zero?
      flag, chunk_parts, chunk_length = decode_chunk buffer
      chunk_list << chunk_parts unless chunk_parts.empty?

      if flag.successed?
        buffer.pos = before_buffer_pos
        return chunk_list.flatten.join "."
      end

      if flag.resource_pointer?
        next update_chunk_resource_pointer_position protocol, buffer, chunk_length, question
      end

      buffer.pos = before_buffer_pos
      break
    end
  end

  def self.limit_length_buffer(io : IO, length : Int) : IO::Memory
    limit_length_buffer! io, length rescue IO::Memory.new 0_i32
  end

  def self.limit_length_buffer!(io : IO, length : Int) : IO::Memory
    temporary = IO::Memory.new
    IO.copy io, temporary, length

    temporary.rewind
    temporary
  end

  def self.encode_chunk_ipv4_address(ip_address, io : IO)
    return io.write Bytes[0_u8] unless ip_address
    return io.write Bytes[0_u8] if ip_address.empty?

    parts = ip_address.split "."
    parts.pop if parts.last.empty?

    parts.each do |part|
      io.write_bytes part.size.to_u8
      io << part
    end

    io.write Bytes[0_i32]
  end

  def self.parse_strict_length_address(protocol : Protocol, io : IO, length : Int, buffer : IO::Memory,
                                       maximum_depth : Int32 = 65_i32, maximum_length : Int32 = 512_i32)
    return String.new if length > maximum_length

    temporary = limit_length_buffer io, length
    return String.new if temporary.size != length

    before_buffer_pos = buffer.pos
    buffer.write temporary.to_slice rescue nil

    decoded = depth_decode_by_resource_pointer! protocol, buffer, before_buffer_pos, maximum_depth: maximum_depth
    decoded || String.new
  end

  def self.parse_chunk_address(protocol : Protocol, io : IO, buffer : IO, maximum_depth : Int32 = 65_i32)
    offset_buffer = uninitialized UInt8[1_i32]
    temporary = IO::Memory.new

    loop do
      read_length = io.read offset_buffer.to_slice
      temporary.write offset_buffer.to_slice
      break if offset_buffer.to_slice[0_i32].zero?

      if 0b00000011 == (offset_buffer.to_slice[0_i32] >> 6_i32)
        read_length = io.read offset_buffer.to_slice
        temporary.write offset_buffer.to_slice

        break
      end

      copy_length = IO.copy io, temporary, offset_buffer.to_slice[0_i32]
      break if copy_length != offset_buffer.to_slice[0_i32]
    end

    before_buffer_pos = buffer.pos
    buffer.write temporary.to_slice

    decoded = depth_decode_by_resource_pointer! protocol, buffer, before_buffer_pos, question: true, maximum_depth: maximum_depth
    decoded || String.new
  end
end
