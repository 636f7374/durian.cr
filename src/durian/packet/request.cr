require "../section.cr"

module Durian::Packet
  class Request
    property protocol : Protocol
    property queries : Array(Section::Question)
    property transId : UInt16?
    property operationCode : OperationCode
    property truncated : Truncated
    property recursionDesired : RecursionDesired
    property authenticatedData : AuthenticatedData
    property questionCount : UInt16
    property buffer : IO::Memory?
    property random : Random

    def initialize(@protocol : Protocol = Protocol::UDP)
      @queries = [] of Section::Question
      @transId = nil
      @operationCode = OperationCode::StandardQuery
      @truncated = Truncated::False
      @recursionDesired = RecursionDesired::True
      @authenticatedData = AuthenticatedData::False
      @questionCount = 0_u16
      @buffer = nil
      @random = Random.new
    end

    def add_query(query : String, flag : RecordFlag)
      {% begin %}
        case flag
         {% for name in RecordType %}
        when RecordFlag::{{name.upcase.id}}
          queries << Section::Question.new RecordFlag::{{name.upcase.id}}, query
         {% end %}
        end
      {% end %}
    end

    {% for name in RecordType %}
    def add_{{name.downcase.id}}_query(query : String)
      add_query query, RecordFlag::{{name.upcase.id}}
    end
    {% end %}

    private def self.parse_flags_with_count!(request : Request, io, buffer : IO)
      static_bits = ByteFormat.extract_uint16_bits io, buffer
      bits_io = IO::Memory.new static_bits.to_slice

      qr_flags = bits_io.read_byte || 0_u8
      raise MalformedPacket.new "Non-request Packet" if qr_flags != 0_i32

      operation_code = ByteFormat.parse_four_bit_integer bits_io
      authoritative_answer = bits_io.read_byte || 0_u8
      truncated = bits_io.read_byte || 0_u8
      recursion_desired = bits_io.read_byte || 0_u8
      recursion_available = bits_io.read_byte || 0_u8
      zero = bits_io.read_byte || 0_u8
      authenticated_data = bits_io.read_byte || 0_u8
      checking_disabled = bits_io.read_byte || 0_u8
      response_code = ByteFormat.parse_four_bit_integer bits_io

      request.operationCode = OperationCode.new operation_code
      request.truncated = Truncated.new truncated.to_i32
      request.recursionDesired = RecursionDesired.new recursion_desired.to_i32
      request.authenticatedData = AuthenticatedData.new authenticated_data.to_i32

      request.questionCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      answer_count = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      authority_count = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      additional_count = io.read_bytes UInt16, IO::ByteFormat::BigEndian

      buffer.write_bytes request.questionCount, IO::ByteFormat::BigEndian
      buffer.write_bytes answer_count, IO::ByteFormat::BigEndian
      buffer.write_bytes authority_count, IO::ByteFormat::BigEndian
      buffer.write_bytes additional_count, IO::ByteFormat::BigEndian
    end

    def self.from_io(io : IO, protocol : Protocol = Protocol::UDP,
                     buffer : IO::Memory = IO::Memory.new, sync_buffer_close : Bool = true)
      from_io! io, protocol, buffer, sync_buffer_close rescue nil
    end

    def self.from_io!(io : IO, protocol : Protocol = Protocol::UDP,
                      buffer : IO::Memory = IO::Memory.new, sync_buffer_close : Bool = true)
      request = new
      bad_decode = false

      begin
        length = io.read_bytes UInt16, IO::ByteFormat::BigEndian if protocol.tcp?
        trans_id = io.read_bytes UInt16, IO::ByteFormat::BigEndian

        buffer.write_bytes length, IO::ByteFormat::BigEndian if length
        buffer.write_bytes trans_id, IO::ByteFormat::BigEndian
      rescue ex
        raise MalformedPacket.new ex.message
      end

      request.transId = trans_id
      parse_flags_with_count! request, io, buffer

      request.questionCount.times do
        break if bad_decode

        request.queries << Section::Question.decode io, buffer rescue bad_decode = true
      end

      buffer.close if sync_buffer_close
      request.buffer = buffer unless sync_buffer_close
      request
    end

    def to_slice
      io = IO::Memory.new
      to_io io
      io.to_slice
    end

    def to_io(io : IO)
      case protocol
      when .udp?
        to_udp_io io
      when .tcp?
        temporary = IO::Memory.new
        to_udp_io temporary
        length = temporary.size.to_u16
        io.write_bytes length, IO::ByteFormat::BigEndian
        io.write temporary.to_slice
      end
    end

    # Request
    # DNS QUERY MESSAGE FORMAT: http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/160-protocols-dns-query.html
    # Protocol and Format: http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html
    # How to convert a string or integer to binary in Ruby?: https://stackoverflow.com/questions/2339695/how-to-convert-a-string-or-integer-to-binary-in-ruby
    # Numbers: http://www.oualline.com/practical.programmer/numbers.html
    # DNS Query Code in C with linux sockets: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

    def to_udp_io(io : IO)
      # Identification field is used to match up replies and requests.
      @transId = random.rand UInt16 unless transId
      if _trans_id = transId
        io.write_bytes _trans_id, IO::ByteFormat::BigEndian
      end

      # Control field contains: QR | OpCode | AA | TC | RD | RA | Z | AD | CD | RCODE
      flags = String.bits_build do |io|
        # QR : 1 bit, request (0) or response (1)
        # Request not required, set to 1 Zero
        io << QRFlag::Query.to_i.to_s

        # OpCode : 4 bits, request type
        # |_ QUERY_ Standard request
        # |_ IQUERY Inverse request (obsoleted by RFC3425)
        # |_ STATUS Server status query
        # |_ NOTIFY Database update notification (RFC1996)
        # |_ UPDATE Dynamic database update (RFC2136)
        io << "%04b" % operationCode.to_i.to_s

        # AA Authoritative Answer : 1 bit, reply from authoritative (1) or from cache (0)
        # Request not required, set to 1 Zero
        io << "0"

        # TC Truncated : 1 bit, response too large for UDP (1).
        io << truncated.to_i.to_s

        # RD Recursion Desired: 1bit, ask for recursive (1) or iterative (0) response
        io << recursionDesired.to_i.to_s

        # RA Recursion Available : 1bit, server manages recursive (1) or not (0)
        # Request not required, set to 1 Zero
        io << "0"

        # 1 bit Zeros, reserved for extensions
        # Request not required, set to 1 Zero
        io << "0"

        # 1 bit AD Authenticated data, used by DNSSEC
        io << authenticatedData.to_i.to_s

        # 1 bit CD Checking Disabled, used by DNSSEC
        # Request not required, set to 1 Zero
        io << "0"

        # 4 bits Rcode, Error Codes : NOERROR, SERVFAIL, NXDOMAIN (no such domain), REFUSED...
        # Request not required, set to 4 Zero
        io << "0000"
      end

      io.write_bytes flags || 256_u16, IO::ByteFormat::BigEndian

      # ... count fields give the number of entry in each following sections:
      # Question count
      io.write_bytes queries.size.to_u16, IO::ByteFormat::BigEndian

      # Answer count
      io.write_bytes 0_u16, IO::ByteFormat::BigEndian

      # Authority count
      io.write_bytes 0_u16, IO::ByteFormat::BigEndian

      # Additional count
      io.write_bytes 0_u16, IO::ByteFormat::BigEndian

      # Question count equals to 1 in general, but could be 0 or > 1 in very special cases
      queries.each &.encode io
    end
  end
end
