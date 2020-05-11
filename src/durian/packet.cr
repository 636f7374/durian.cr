class Durian::Packet
  enum QRFlag : UInt16
    Query    = 0b0000000000000000_u16
    Response = 0b1000000000000000_u16
  end

  enum OperationCode : UInt16
    StandardQuery = 0b0000000000000000_u16
    InverseQuery  = 0b0000100000000000_u16
    Status        = 0b0001000000000000_u16
    Reserved      = 0b0001100000000000_u16
    Notify        = 0b0010000000000000_u16
    Update        = 0b0010100000000000_u16
  end

  enum AuthoritativeAnswer : UInt16
    False = 0b0000000000000000_u16
    True  = 0b0000010000000000_u16
  end

  enum Truncated : UInt16
    False = 0b0000000000000000_u16
    True  = 0b0000001000000000_u16
  end

  enum RecursionDesired : UInt16
    False = 0b0000000000000000_u16
    True  = 0b0000000100000000_u16
  end

  enum RecursionAvailable : UInt16
    False = 0b0000000000000000_u16
    True  = 0b0000000010000000_u16
  end

  enum AuthenticatedData : UInt16
    False = 0b0000000000000000_u16
    True  = 0b0000000000100000_u16
  end

  enum CheckingDisabled : UInt16
    False = 0b0000000000000000_u16
    True  = 0b0000000000010000_u16
  end

  enum Error : UInt16
    NoError        = 0b0000000000000000_u16
    FormatError    = 0b0000000000000001_u16
    ServerFailure  = 0b0000000000000010_u16
    NameError      = 0b0000000000000011_u16
    NotImplemented = 0b0000000000000100_u16
    Refused        = 0b0000000000000101_u16
    YXDomain       = 0b0000000000000110_u16
    YXRRSet        = 0b0000000000000111_u16
    NXRRSet        = 0b0000000000001000_u16
    NotAuth        = 0b0000000000001001_u16
    NotZone        = 0b0000000000001010_u16
  end

  property protocol : Protocol
  property qrFlag : QRFlag
  property queries : Array(Section::Question)
  property answers : Array(Section::Answer)
  property authority : Array(Section::Authority)
  property additional : Array(Section::Additional)
  property transId : UInt16
  property operationCode : OperationCode
  property error : Error
  property authoritativeAnswer : AuthoritativeAnswer
  property truncated : Truncated
  property recursionDesired : RecursionDesired
  property recursionAvailable : RecursionAvailable
  property authenticatedData : AuthenticatedData
  property checkingDisabled : CheckingDisabled
  property questionCount : UInt16
  property answerCount : UInt16
  property authorityCount : UInt16
  property additionalCount : UInt16
  property buffer : IO::Memory?

  def initialize(@protocol : Protocol = Protocol::UDP, @qrFlag : QRFlag = QRFlag::Query)
    @queries = [] of Section::Question
    @answers = [] of Section::Answer
    @authority = [] of Section::Authority
    @additional = [] of Section::Additional
    @transId = Random.new.rand UInt16
    @operationCode = OperationCode::StandardQuery
    @error = Error::NoError
    @authoritativeAnswer = AuthoritativeAnswer::False
    @truncated = Truncated::False
    @recursionDesired = RecursionDesired::True
    @recursionAvailable = RecursionAvailable::False
    @authenticatedData = AuthenticatedData::False
    @checkingDisabled = CheckingDisabled::False
    @questionCount = 0_u16
    @answerCount = 0_u16
    @authorityCount = 0_u16
    @additionalCount = 0_u16
    @buffer = nil
  end

  def add_query(query : String, flag : RecordFlag)
    {% begin %}
      case flag
        {% for name in AvailableRecordFlag %}
      when RecordFlag::{{name.upcase.id}}
        queries << Section::Question.new RecordFlag::{{name.upcase.id}}, query
        {% end %}
      else
      end
    {% end %}
  end

  {% for name in AvailableRecordFlag %}
  def add_{{name.downcase.id}}_query(query : String)
    add_query query, RecordFlag::{{name.upcase.id}}
  end
  {% end %}

  private def self.parse_flags_count!(packet : Packet, io, buffer : IO::Memory)
    # * Read Flags (2 Bytes)

    begin
      flags = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    rescue ex
      raise BadPacket.new ex.message
    end

    # * Write Flags (2 Bytes)

    buffer.write_bytes flags, IO::ByteFormat::BigEndian

    # * Parse Flag (QRFlag)

    packet.qrFlag = QRFlag.new (flags & QRFlag::Response.value)

    # * Parse Flag (Miscellaneous)

    packet.operationCode = OperationCode.new (flags >> 11_i32) & 0x0f_u16
    packet.authoritativeAnswer = AuthoritativeAnswer.new flags & AuthoritativeAnswer::True.value
    packet.truncated = Truncated.new flags & Truncated::True.value
    packet.recursionDesired = RecursionDesired.new flags & RecursionDesired::True.value
    packet.recursionAvailable = RecursionAvailable.new flags & RecursionAvailable::True.value
    packet.authenticatedData = AuthenticatedData.new flags & AuthenticatedData::True.value
    packet.checkingDisabled = CheckingDisabled.new flags & CheckingDisabled::True.value
    packet.error = Error.new flags & 0x0f_u16

    # * Read Count (8 Bytes)

    packet.questionCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    packet.answerCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    packet.authorityCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    packet.additionalCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian

    # * Write Count (8 Bytes)

    buffer.write_bytes packet.questionCount, IO::ByteFormat::BigEndian
    buffer.write_bytes packet.answerCount, IO::ByteFormat::BigEndian
    buffer.write_bytes packet.authorityCount, IO::ByteFormat::BigEndian
    buffer.write_bytes packet.additionalCount, IO::ByteFormat::BigEndian
  end

  def self.from_io(protocol : Protocol, qr_flag : QRFlag, io : IO, buffer : IO::Memory = IO::Memory.new) : Packet?
    from_io! protocol, qr_flag, io, buffer rescue nil
  end

  def self.from_io!(protocol : Protocol, qr_flag : QRFlag, io : IO, buffer : IO::Memory = IO::Memory.new) : Packet
    packet = new protocol: protocol, qrFlag: qr_flag
    bad_decode = false

    begin
      length = io.read_bytes UInt16, IO::ByteFormat::BigEndian if protocol.tcp?
      trans_id = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    rescue ex
      raise MalformedPacket.new ex.message
    end

    buffer.write_bytes length, IO::ByteFormat::BigEndian if length
    buffer.write_bytes trans_id, IO::ByteFormat::BigEndian

    packet.transId = trans_id
    parse_flags_count! packet, io, buffer

    packet.questionCount.times do
      break if bad_decode

      packet.queries << Section::Question.decode io, buffer rescue bad_decode = true
    end

    packet.answerCount.times do
      break if bad_decode

      packet.answers << Section::Answer.decode io, buffer rescue bad_decode = true
    end

    packet.authorityCount.times do
      break if bad_decode

      packet.authority << Section::Authority.decode io, buffer rescue bad_decode = true
    end

    packet.additionalCount.times do
      break if bad_decode

      packet.additional << Section::Additional.decode io, buffer rescue bad_decode = true
    end

    packet.buffer = buffer
    packet
  end

  def to_slice : Bytes
    io = IO::Memory.new
    to_io io

    io.to_slice
  end

  def to_io(io : IO)
    case protocol
    when .udp?
      to_io io, qrFlag
    when .tcp?
      temporary = IO::Memory.new
      to_io temporary, qrFlag
      length = temporary.size.to_u16
      io.write_bytes length, IO::ByteFormat::BigEndian
      io.write temporary.to_slice
    end
  end

  private def to_io(io : IO, qr_flag : QRFlag)
    qr_flag.query? ? (to_io_query io) : (to_io_response io)
  end

  # * Request:
  #   * DNS QUERY MESSAGE FORMAT: http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/160-protocols-dns-query.html
  #   * Protocol and Format: http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html
  #   * How to convert a string or integer to binary in Ruby?: https://stackoverflow.com/questions/2339695/how-to-convert-a-string-or-integer-to-binary-in-ruby
  #   * Numbers: http://www.oualline.com/practical.programmer/numbers.html
  #   * DNS Query Code in C with linux sockets: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

  private def to_io_query(io : IO)
    # * Write transId (2 Bytes)

    io.write_bytes transId, IO::ByteFormat::BigEndian

    # * Control field contains: QR | OpCode | AA | TC | RD | RA | Z | AD | CD | RCODE

    flags = 0b0000000000000000_u16

    # * QR : 1 bit, request (0) or response (1)
    #   * Request not required, set to 1 Zero

    flags = flags | qrFlag.value

    # * OpCode : 4 bits, request type
    #   * |_ QUERY_ Standard request
    #   * |_ IQUERY Inverse request (obsoleted by RFC3425)
    #   * |_ STATUS Server status query
    #   * |_ NOTIFY Database update notification (RFC1996)
    #   * |_ UPDATE Dynamic database update (RFC2136)

    flags = flags | operationCode.value

    # * AA Authoritative Answer : 1 bit, reply from authoritative (1) or from cache (0)
    #   * Request not required, set to 1 Zero

    flags = flags | authoritativeAnswer.value

    # * TC Truncated : 1 bit, response too large for UDP (1).

    flags = flags | truncated.value

    # * RD Recursion Desired: 1bit, ask for recursive (1) or iterative (0) response

    flags = flags | recursionDesired.value

    # * RA Recursion Available : 1bit, server manages recursive (1) or not (0)
    #   * Request not required, set to 1 Zero

    flags = flags | recursionAvailable.value

    # * 1 bit Zeros, reserved for extensions
    #   * Request not required, set to 1 Zero

    flags = flags | 0b0000000000000000_u16

    # * 1 bit AD Authenticated data, used by DNSSEC

    flags = flags | authenticatedData.value

    # * 1 bit CD Checking Disabled, used by DNSSEC
    #   * Request not required, set to 1 Zero

    flags = flags | checkingDisabled.value

    # * 4 bits Rcode, Error Codes : NOERROR, SERVFAIL, NXDOMAIN (no such domain), REFUSED...
    #   * Request not required, set to 4 Zero

    flags = flags | error.value

    # * Write flags (2 Bytes)

    io.write_bytes flags, IO::ByteFormat::BigEndian

    # * ... count fields give the number of entry in each following sections:
    #   * Question Count (2 Bytes)
    io.write_bytes queries.size.to_u16, IO::ByteFormat::BigEndian

    #   * Answer count (2 Bytes)
    io.write_bytes 0_u16, IO::ByteFormat::BigEndian

    #   * Authority count (2 Bytes)
    io.write_bytes 0_u16, IO::ByteFormat::BigEndian

    #   * Additional count (2 Bytes)
    io.write_bytes 0_u16, IO::ByteFormat::BigEndian

    # * Question count equals to 1 in general, but could be 0 or > 1 in very special cases
    queries.each &.encode io
  end

  private def to_io_response(io : IO)
    raise Exception.new "Currently, the QRFlag Response to_io feature is not supported"
  end
end
