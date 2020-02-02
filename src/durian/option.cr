class Durian::Option
  include YAML::Serializable

  property timeout : TimeOut
  property addrinfo : Addrinfo
  property retry : Retry?

  def initialize
    @timeout = TimeOut.new
    @addrinfo = Addrinfo.new
    @retry = nil
  end

  class Addrinfo
    include YAML::Serializable

    property withIpv6 : Bool

    def initialize
      @withIpv6 = false
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
end
