class Durian::Option
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
end
