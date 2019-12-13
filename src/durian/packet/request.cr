require "../section.cr"

module Durian::Packet
  class Request
    property queries : Array(Section::Question)
    property transId : UInt16?
    property operationCode : OperationCode
    property truncated : Truncated
    property recursionDesired : RecursionDesired
    property authenticatedData : AuthenticatedData
    property questionCount : UInt16
    property buffer : IO::Memory?
    property random : Random

    def initialize
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

    def add_query(query : String, flag : Record::ResourceFlag)
      {% begin %}
        case flag
         {% for name in RecordType %}
        when Record::ResourceFlag::{{name.upcase.id}}
          queries << Section::Question.new Record::ResourceFlag::{{name.upcase.id}}, query
         {% end %}
        end
      {% end %}
    end

    {% for name in RecordType %}
    def add_{{name.downcase.id}}_query(query : String)
      add_query query, Record::ResourceFlag::{{name.upcase.id}}
    end
    {% end %}

    private def self.parse_flags_with_count!(request : Request, io, buffer : IO)
      begin
        temporary = Durian.parse_bit_flags io, buffer
        qr_flags = temporary.read_byte || 0_u8
        operation_code = Durian.parse_four_bit_integer temporary
        authoritative_answer = temporary.read_byte || 0_u8
        truncated = temporary.read_byte || 0_u8
        recursion_desired = temporary.read_byte || 0_u8
        recursion_available = temporary.read_byte || 0_u8
        zero = temporary.read_byte || 0_u8
        authenticated_data = temporary.read_byte || 0_u8
        checking_disabled = temporary.read_byte || 0_u8
        response_code = Durian.parse_four_bit_integer temporary
      rescue ex
        temporary.try &.close ensure raise ex
      end

      request.operationCode = OperationCode.new operation_code
      request.truncated = Truncated.new truncated
      request.recursionDesired = RecursionDesired.new recursion_desired
      request.authenticatedData = AuthenticatedData.new authenticated_data

      begin
        request.questionCount = io.read_network_short
        answer_count = io.read_network_short
        authority_count = io.read_network_short
        additional_count = io.read_network_short
      rescue ex
        temporary.try &.close ensure raise ex
      end
    end

    def self.from_io(io : IO, buffer : IO::Memory = IO::Memory.new, sync_buffer_close : Bool = true)
      from_io! io, buffer, sync_buffer_close rescue nil
    end

    def self.from_io!(io : IO, buffer : IO::Memory = IO::Memory.new, sync_buffer_close : Bool = true)
      request = new
      bad_decode = false

      begin
        trans_id = io.read_network_short
        buffer.write_network_short trans_id
      rescue ex
        buffer.close
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

      begin
        to_io io
      rescue ex
        io.close
        raise ex
      end

      slice = io.to_slice

      io.close
      slice
    end

    # Request
    # DNS QUERY MESSAGE FORMAT: http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/160-protocols-dns-query.html
    # Protocol and Format: http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html
    # How to convert a string or integer to binary in Ruby?: https://stackoverflow.com/questions/2339695/how-to-convert-a-string-or-integer-to-binary-in-ruby
    # Numbers: http://www.oualline.com/practical.programmer/numbers.html
    # DNS Query Code in C with linux sockets: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

    def to_io(io : IO)
      # Identification field is used to match up replies and requests.
      @transId = random.rand UInt16 unless transId
      io.write_network_short transId || random.rand UInt16

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

      io.write_network_short flags || 256_i32

      # ... count fields give the number of entry in each following sections:
      # Question count
      io.write_network_short queries.size

      # Answer count
      io.write_network_short 0_i32

      # Authority count
      io.write_network_short 0_i32

      # Additional count
      io.write_network_short 0_i32

      # Question count equals to 1 in general, but could be 0 or > 1 in very special cases
      queries.each &.encode io
    end
  end
end
