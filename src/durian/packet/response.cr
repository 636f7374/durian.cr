module Durian::Packet
  class Response
    property protocol : Protocol
    property queries : Array(Section::Question)
    property answers : Array(Section::Answer)
    property authority : Array(Section::Authority)
    property additional : Array(Section::Additional)
    property transId : UInt16?
    property operationCode : OperationCode
    property responseCode : ResponseCode
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

    def initialize(@protocol : Protocol = Protocol::UDP)
      @queries = [] of Section::Question
      @answers = [] of Section::Answer
      @authority = [] of Section::Authority
      @additional = [] of Section::Additional
      @transId = nil
      @operationCode = OperationCode::StandardQuery
      @responseCode = ResponseCode::NoError
      @authoritativeAnswer = AuthoritativeAnswer::False
      @truncated = Truncated::False
      @recursionDesired = RecursionDesired::False
      @recursionAvailable = RecursionAvailable::False
      @authenticatedData = AuthenticatedData::False
      @checkingDisabled = CheckingDisabled::False
      @questionCount = 0_u16
      @answerCount = 0_u16
      @authorityCount = 0_u16
      @additionalCount = 0_u16
      @buffer = nil
    end

    private def self.parse_flags_count!(response : Response, io, buffer : IO)
      begin
        flags = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      rescue ex
        raise BadPacket.new ex.message
      end

      buffer.write_bytes flags, IO::ByteFormat::BigEndian

      # QrFlag
      raise MalformedPacket.new "Non-response Packet" if (flags & 0x8000_u16) != 0x8000_u16

      # Miscellaneous
      response.operationCode = OperationCode.new (flags >> 11_i32) & 0x0f_u16
      response.authoritativeAnswer = AuthoritativeAnswer.new flags & 0x0400_u16
      response.truncated = Truncated.new flags & 0x0200_u16
      response.recursionDesired = RecursionDesired.new flags & 0x0100_u16
      response.recursionAvailable = RecursionAvailable.new flags & 0x0080_u16
      response.authenticatedData = AuthenticatedData.new flags & 0x0020_u16
      response.checkingDisabled = CheckingDisabled.new flags & 0x0010_u16
      response.responseCode = ResponseCode.new flags & 0x0f_u16

      # Count
      response.questionCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      response.answerCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      response.authorityCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      response.additionalCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian

      buffer.write_bytes response.questionCount, IO::ByteFormat::BigEndian
      buffer.write_bytes response.answerCount, IO::ByteFormat::BigEndian
      buffer.write_bytes response.authorityCount, IO::ByteFormat::BigEndian
      buffer.write_bytes response.additionalCount, IO::ByteFormat::BigEndian
    end

    def self.from_io(io : IO, protocol : Protocol = Protocol::UDP,
                     buffer : IO::Memory = IO::Memory.new, sync_buffer_close : Bool = true)
      from_io! io, protocol, buffer, sync_buffer_close rescue nil
    end

    def self.from_io!(io : IO, protocol : Protocol = Protocol::UDP,
                      buffer : IO::Memory = IO::Memory.new, sync_buffer_close : Bool = true)
      response = new
      response.protocol = protocol
      bad_decode = false

      begin
        length = io.read_bytes UInt16, IO::ByteFormat::BigEndian if protocol.tcp?
        trans_id = io.read_bytes UInt16, IO::ByteFormat::BigEndian

        buffer.write_bytes trans_id, IO::ByteFormat::BigEndian
      rescue ex
        raise MalformedPacket.new ex.message
      end

      response.transId = trans_id
      parse_flags_count! response, io, buffer

      response.questionCount.times do
        break if bad_decode

        response.queries << Section::Question.decode io, buffer rescue bad_decode = true
      end

      response.answerCount.times do
        break if bad_decode

        response.answers << Section::Answer.decode io, buffer rescue bad_decode = true
      end

      response.authorityCount.times do
        break if bad_decode

        response.authority << Section::Authority.decode io, buffer rescue bad_decode = true
      end

      response.additionalCount.times do
        break if bad_decode

        response.additional << Section::Additional.decode io, buffer rescue bad_decode = true
      end

      buffer.close if sync_buffer_close
      response.buffer = buffer unless sync_buffer_close
      response
    end
  end
end
