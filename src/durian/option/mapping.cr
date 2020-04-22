class Durian::Option
  class Mapping
    property from : String
    property to : String?
    property local : Array(Socket::IPAddress)?
    property isRegex : Bool?
    property isStrict : Bool?
    property withPort : Bool?

    def initialize
      @from = String.new
      @to = nil
      @local = nil
      @isRegex = nil
      @isStrict = nil
      @withPort = nil
    end
  end
end
