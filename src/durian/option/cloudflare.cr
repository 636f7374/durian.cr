class Durian::Option
  class Cloudflare
    include YAML::Serializable

    property from : String
    property isRegex : Bool?
    property isStrict : Bool?
    property withPort : Bool?

    def initialize
      @from = String.new
      @isRegex = nil
      @isStrict = nil
      @withPort = nil
    end
  end
end
