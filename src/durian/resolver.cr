class Durian::Resolver
  IPAddressRecordFlags = [RecordFlag::A, RecordFlag::AAAA]

  alias ResolveResponse = Array(Tuple(String, RecordFlag, Packet::Response))
  alias ResolveTask = Tuple(Array(RecordFlag), Proc(ResolveResponse, Nil))
  alias NetworkClient = Network::TCPClient | Network::UDPClient
  alias AliasServer = Hash(String, String | Array(Socket::IPAddress))

  property dnsServers : Array(Tuple(Socket::IPAddress, Protocol))
  property random : Random
  property tasks : Hash(String, Hash(String, ResolveTask))

  def initialize(@dnsServers : Array(Tuple(Socket::IPAddress, Protocol)))
    @random = Random.new
    @tasks = Hash(String, Hash(String, ResolveTask)).new
  end

  def self.new(dnsServer : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32), protocol : Protocol = Protocol::UDP)
    new [Tuple.new dnsServer, protocol]
  end

  def read_timeout=(value : Int32)
    @read_timeout = value.seconds
  end

  def read_timeout=(value : Time::Span)
    @read_timeout = value
  end

  def read_timeout
    @read_timeout || default_read_timeout
  end

  def default_read_timeout
    2_i32.seconds
  end

  def write_timeout=(value : Int32)
    @write_timeout = value.seconds
  end

  def write_timeout=(value : Time::Span)
    @write_timeout = value
  end

  def write_timeout
    @write_timeout || default_write_timeout
  end

  def default_write_timeout
    2_i32.seconds
  end

  def connect_timeout=(value : Int32)
    @connect_timeout = value.seconds
  end

  def connect_timeout=(value : Time::Span)
    @connect_timeout = value
  end

  def connect_timeout
    @connect_timeout || default_connect_timeout
  end

  def default_connect_timeout
    5_i32.seconds
  end

  def cache=(value : Cache)
    @cache = value
  end

  def cache
    @cache
  end

  def ip_cache(value : Cache::IPAddress)
    @ip_cache = value
  end

  def ip_cache
    @ip_cache
  end

  def ip_cache=(value : Cache::IPAddress)
    @ip_cache = value
  end

  def ip_cache
    @ip_cache
  end

  def mismatch_retry_count=(value : Int32)
    @mismatchRetryCount = value
  end

  def mismatch_retry_count
    @mismatchRetryCount || default_mismatch_retry_count
  end

  def default_mismatch_retry_count
    5_i32
  end

  def refresh
    @cleanAt = Time.local
  end

  def resolve_by_flag!(host : String, flag : RecordFlag)
    dnsServers.each do |server|
      socket = Network.create_client server, read_timeout, write_timeout, connect_timeout rescue nil
      next unless socket

      next socket.close unless packet = resolve_by_flag! socket, host, flag rescue nil

      socket.close
      break packet
    end
  end

  def resolve_by_flag!(socket : NetworkClient, host : String, flag : RecordFlag) : Packet::Response?
    buffer = uninitialized UInt8[4096_i32]

    request = Packet::Request.new
    request.add_query host, flag
    socket.send request.to_slice

    mismatch_retry_count.times do
      length, address = socket.receive buffer.to_slice
      length = 0_i32 unless length

      io = IO::Memory.new buffer.to_slice[0_i32, length]
      response = Packet::Response.from_io io
      io.close

      unless response
        next if socket.is_a? Network::UDPClient
        return
      end

      return response if request.transId == response.transId
    end
  end

  private def self.extract_canonical_name_ip_address(host : String, alias_server : AliasServer,
                                                     list : Array(Socket::IPAddress))
    _alias = alias_server[host]?
    return unless _alias

    loop do
      _next = alias_server[_alias]?
      break unless _next
      next _alias = _next if _next.is_a? String

      if _next.is_a? Array(Socket::IPAddress)
        break _next.each do |data|
          list << data
        end
      end
    end
  end

  private def self.extract_all_ip_address(host : String, port : Int32, resolve_response : ResolveResponse,
                                          list : Array(Socket::IPAddress))
    resolve_response.each do |response|
      host, flag, response = response
      alias_server = AliasServer.new

      response.answers.each do |answers|
        _record = answers.resourceRecord
        next unless from = _record.from

        case _record
        when Record::AAAA
          if _record.responds_to? :ipv6Address
            _ip_address = Socket::IPAddress.new _record.ipv6Address, port rescue nil
            next unless _ip_address
            next list << _ip_address if host == from

            unless alias_server[from]?
              alias_server[from] = Array(Socket::IPAddress).new
            end

            if alias_server[from].is_a? Array(Socket::IPAddress)
              alias_server[from].as Array(Socket::IPAddress) << _ip_address
            end
          end
        when Record::A
          if _record.responds_to? :ipv4Address
            _ip_address = Socket::IPAddress.new _record.ipv4Address, port rescue nil
            next unless _ip_address
            next list << _ip_address if host == from

            unless alias_server[from]?
              alias_server[from] = Array(Socket::IPAddress).new
            end

            if alias_server[from].is_a? Array(Socket::IPAddress)
              alias_server[from].as Array(Socket::IPAddress) << _ip_address
            end
          end
        when Record::CNAME
          if _record.responds_to? :canonicalName
            alias_server[from] = _record.canonicalName
          end
        end
      end

      extract_canonical_name_ip_address host, alias_server, list
      alias_server.clear
    end
  end

  def self.fetch_ip_cache(host : String, port : Int32, ip_cache : Cache::IPAddress?)
    return unless ip_cache
    return if ip_cache.expires? host

    ip_cache.get host, port
  end

  def self.getaddrinfo(host : String, port : Int32, ip_cache : Cache::IPAddress? = nil,
                       dnsServer : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32),
                       protocol : Protocol = Protocol::UDP,
                       &block : Array(Socket::IPAddress) ->)
    yield getaddrinfo host, port, ip_cache, [Tuple.new dnsServer, protocol]
  end

  def self.getaddrinfo(host : String, port : Int32, ip_cache : Cache::IPAddress? = nil,
                       dnsServer : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32),
                       protocol : Protocol = Protocol::UDP) : Array(Socket::IPAddress)
    getaddrinfo host, port, ip_cache, [Tuple.new dnsServer, protocol]
  end

  def self.getaddrinfo(host : String, port : Int32, ip_cache : Cache::IPAddress?,
                       dnsServers : Array(Tuple(Socket::IPAddress, Protocol)),
                       &block : Array(Socket::IPAddress) ->)
    yield getaddrinfo host, port, ip_cache, dnsServers
  end

  def self.getaddrinfo(host : String, port : Int32, ip_cache : Cache::IPAddress?,
                       dnsServers : Array(Tuple(Socket::IPAddress, Protocol))) : Array(Socket::IPAddress)
    resolver = new dnsServers
    resolver.ip_cache = ip_cache if ip_cache

    getaddrinfo host, port, resolver
  end

  def self.getaddrinfo(host : String, port : Int32, resolver : Resolver,
                       &block : Array(Socket::IPAddress) ->)
    yield getaddrinfo host, port, resolver
  end

  def self.getaddrinfo(host : String, port : Int32, resolver : Resolver) : Array(Socket::IPAddress)
    list = [] of Socket::IPAddress
    list << Socket::IPAddress.new host, port rescue nil
    return list unless list.empty?

    from_ip_cache = fetch_ip_cache host, port, resolver.ip_cache
    return from_ip_cache unless from_ip_cache.empty? if from_ip_cache

    resolver.resolve_task host, Tuple.new IPAddressRecordFlags, ->(resolve_response : ResolveResponse) do
      extract_all_ip_address host, port, resolve_response, list
    end

    if ip_cache = resolver.ip_cache
      ip_cache.set host, list unless list.empty?
    end

    list
  end

  def to_ip_address(host : String)
    Socket::IPAddress.new host, 0_i32 rescue nil
  end

  def set_cache(host, packet : Packet::Response, flag : RecordFlag)
    return unless _cache = cache

    _cache.set host, packet, flag
  end

  def fetch_raw_cache(host, flag : RecordFlag)
    return unless _cache = cache

    _cache.get host, flag
  end

  def cache_expires?(host, flags : Array(RecordFlag))
    expires = [] of RecordFlag
    return expires unless _cache = cache

    flags.each do |flag|
      expires << flag if _cache.expires? host, flag
    end

    expires
  end

  def fetch_cache(host, flags : Array(RecordFlag), resolve_response : ResolveResponse)
    flags = flags - cache_expires? host, flags
    fetch = [] of RecordFlag

    flags.each do |flag|
      packet = fetch_raw_cache host, flag

      if packet
        resolve_response << Tuple.new host, flag, packet
        fetch << flag
      end
    end

    fetch
  end

  def resolve_task(host : String, task : ResolveTask)
    packets = [] of Tuple(String, RecordFlag, Packet::Response)
    flags, proc = task

    cache_fetch = fetch_cache host, flags, packets
    return proc.call packets if cache_fetch.size == flags.size

    flags = flags - cache_fetch
    ip_address = to_ip_address host

    flags.each do |flag|
      next if cache_fetch.includes? flag
      next if ip_address && IPAddressRecordFlags.includes? flag
      next unless packet = resolve_by_flag! host, flag

      packets << Tuple.new host, flag, packet
      set_cache host, packet, flag
    end

    proc.call packets
  end

  def resolve(host, flag : RecordFlag, &callback : ResolveResponse ->)
    tasks[host] = Hash(String, ResolveTask).new unless tasks[host]?
    tasks[host][random.hex] = Tuple.new [flag], callback
  end

  def resolve(host, flags : Array(RecordFlag), &callback : ResolveResponse ->)
    tasks[host] = Hash(String, ResolveTask).new unless tasks[host]?
    tasks[host][random.hex] = Tuple.new flags, callback
  end

  private def handle_task(channel : Channel(Nil), host : String,
                          task : Hash(String, ResolveTask))
    task.each do |id, sub_task|
      spawn do
        resolve_task host, sub_task
        task.delete id
      ensure
        channel.send nil
      end

      channel.receive
    end
  end

  private def clean_tasks(tasks : Hash(String, Hash(String, ResolveTask)))
    tasks.each do |host, task|
      tasks.delete host if task.empty?
    end
  end

  def run
    channel = Channel(Nil).new

    tasks.each do |host, task|
      handle_task channel, host, task
    end

    clean_tasks tasks
    channel.close
  end
end

require "./resolver/*"
