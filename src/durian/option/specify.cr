class Durian::Option
  class Specify
    property from : String
    property throughs : Array(Resolver::Server)
    property isRegex : Bool?
    property isStrict : Bool?
    property withPort : Bool?

    def initialize
      @from = String.new
      @throughs = [] of Resolver::Server
      @isRegex = nil
      @isStrict = nil
      @withPort = nil
    end
  end
end
