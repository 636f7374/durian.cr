class Durian::Option
  include YAML::Serializable

  property cloudflare : Array(Cloudflare)
  property timeout : TimeOut
  property addrinfo : Addrinfo
  property retry : Retry?
  property mapping : Array(Mapping)
  property specify : Array(Specify)

  def initialize
    @cloudflare = [] of Cloudflare
    @timeout = TimeOut.new
    @addrinfo = Addrinfo.new
    @retry = nil
    @mapping = [] of Mapping
    @specify = [] of Specify
  end

  class Addrinfo
    include YAML::Serializable

    property withIpv6 : Bool

    def initialize
      @withIpv6 = false
    end
  end

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

  class Specify
    property from : String
    property through : Array(Tuple(Socket::IPAddress, Protocol))
    property isRegex : Bool?
    property isStrict : Bool?
    property withPort : Bool?

    def initialize
      @from = String.new
      @through = [] of Tuple(Socket::IPAddress, Protocol)
      @isRegex = nil
      @isStrict = nil
      @withPort = nil
    end
  end

  class Retry
    include YAML::Serializable

    property mismatch : Int32
    property maximumIpv6 : Int32
    property maximumIpv4 : Int32
    property timeout : Int32

    def initialize
      @mismatch = 5_i32
      @maximumIpv4 = 2_i32
      @maximumIpv6 = 2_i32
      @timeout = 1_i32
    end
  end

  class TimeOut
    include YAML::Serializable

    property read : Int32
    property write : Int32
    property connect : Int32

    def initialize
      @read = 2_i32
      @write = 2_i32
      @connect = 5_i32
    end
  end

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
