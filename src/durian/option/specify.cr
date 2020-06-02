class Durian::Option
  class Specify
    property from : String
    property throughs : Array(Tuple(Socket::IPAddress, Protocol))
    property isRegex : Bool?
    property isStrict : Bool?
    property withPort : Bool?

    def initialize
      @from = String.new
      @throughs = [] of Tuple(Socket::IPAddress, Protocol)
      @isRegex = nil
      @isStrict = nil
      @withPort = nil
    end
  end
end
