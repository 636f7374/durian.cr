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
end
