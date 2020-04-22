class Durian::Option
  class Addrinfo
    include YAML::Serializable

    property withIpv6 : Bool

    def initialize
      @withIpv6 = false
    end
  end
end
