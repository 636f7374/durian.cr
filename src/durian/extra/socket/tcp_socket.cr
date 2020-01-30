class TCPSocket < IPSocket
  def initialize(ip_address : IPAddress, dns_timeout = nil, connect_timeout = nil)
    Addrinfo.build_tcp ip_address do |addrinfo|
      super addrinfo.family, addrinfo.type, addrinfo.protocol
      connect(addrinfo, timeout: connect_timeout) do |error|
        close
        error
      end
    end
  end
end
