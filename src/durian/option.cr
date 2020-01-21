class Durian::Option
  include YAML::Serializable

  property timeout : TimeOut
  property addrinfo : Addrinfo
  property mismatchRetryTimes : Int32

  def initialize
    @timeout = TimeOut.new
    @addrinfo = Addrinfo.new
    @mismatchRetryTimes = 5_i32
  end

  class Addrinfo
    include YAML::Serializable

    property withIpv6 : Bool

    def initialize
      @withIpv6 = false
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
