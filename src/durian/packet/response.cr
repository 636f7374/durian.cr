module Durian::Packet
  class Response
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
    property random : Random

    def initialize
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
      @random = Random.new
    end

    private def self.parse_flags_with_count!(response : Response, io, buffer : IO)
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

      response.operationCode = OperationCode.new operation_code
      response.authoritativeAnswer = AuthoritativeAnswer.new authoritative_answer.to_i32
      response.truncated = Truncated.new truncated.to_i32
      response.recursionDesired = RecursionDesired.new recursion_desired.to_i32
      response.recursionAvailable = RecursionAvailable.new recursion_available.to_i32
      response.authenticatedData = AuthenticatedData.new authenticated_data.to_i32
      response.checkingDisabled = CheckingDisabled.new checking_disabled.to_i32
      response.responseCode = ResponseCode.new response_code

      begin
        response.questionCount = io.read_network_short
        response.answerCount = io.read_network_short
        response.authorityCount = io.read_network_short
        response.additionalCount = io.read_network_short

        buffer.write_network_short response.questionCount
        buffer.write_network_short response.answerCount
        buffer.write_network_short response.authorityCount
        buffer.write_network_short response.additionalCount
      rescue ex
        temporary.try &.close ensure raise ex
      end
    end

    def self.from_io(io : IO, buffer : IO::Memory = IO::Memory.new, sync_buffer_close : Bool = true)
      from_io! io, buffer, sync_buffer_close rescue nil
    end

    def self.from_io!(io : IO, buffer : IO::Memory = IO::Memory.new, sync_buffer_close : Bool = true)
      response = new
      bad_decode = false

      begin
        trans_id = io.read_network_short
        buffer.write_network_short trans_id
        response.transId = trans_id
      rescue ex
        buffer.close
        raise MalformedPacket.new ex.message
      end

      parse_flags_with_count! response, io, buffer

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
