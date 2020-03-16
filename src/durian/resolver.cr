class Durian::Resolver
  IPAddressRecordFlags = [RecordFlag::A, RecordFlag::AAAA]

  alias ResolveResponse = Array(Tuple(String, RecordFlag, Packet::Response))
  alias ResolveTask = Tuple(Array(RecordFlag), Bool, Proc(ResolveResponse, Nil))
  alias NetworkClient = Network::TCPClient | Network::UDPClient
  alias AliasServer = Hash(String, String | Array(Socket::IPAddress))

  property dnsServers : Array(Tuple(Socket::IPAddress, Protocol))
  property random : Random
  property tasks : Immutable::Map(String, Immutable::Map(String, ResolveTask))
  property option : Option

  def initialize(@dnsServers : Array(Tuple(Socket::IPAddress, Protocol)))
    @random = Random.new
    @tasks = Immutable::Map(String, Immutable::Map(String, ResolveTask)).new
    @option = Option.new
  end

  def self.new(dnsServer : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32), protocol : Protocol = Protocol::UDP)
    new [Tuple.new dnsServer, protocol]
  end

  def cache=(value : Cache)
    @cache = value
  end

  def cache
    @cache
  end

  def ip_cache=(value : Cache::IPAddress)
    @ip_cache = value
  end

  def ip_cache
    @ip_cache
  end

  def resolve_by_flag!(specify : Array(Tuple(Socket::IPAddress, Protocol))?, host : String,
                       flag : RecordFlag, strict_answer : Bool = false) : Packet::Response?
    servers = specify || dnsServers

    servers.each do |server|
      socket = Network.create_client server, option.timeout rescue nil
      next unless socket

      packet = resolve_by_flag! socket, host, flag rescue nil
      next socket.close unless packet
      next socket.close if packet.answerCount.zero? || packet.answers.empty?

      if strict_answer
        include_flag = false

        packet.answers.each { |answer| break include_flag = true if answer.flag == flag }
        next socket.close unless include_flag
      end

      socket.close
      break packet
    end
  end

  def get_socket_protocol(socket : NetworkClient)
    socket.is_a?(Network::TCPClient) ? Protocol::TCP : Protocol::UDP
  end

  def mismatch_retry
    return 5_i32 unless retry = option.retry

    retry.mismatch
  end

  def resolve_by_flag!(socket : NetworkClient, host : String,
                       flag : RecordFlag, strict_answer : Bool = false) : Packet::Response?
    buffer = uninitialized UInt8[4096_i32]
    protocol = get_socket_protocol(socket) || Protocol::UDP

    request = Packet::Request.new protocol
    request.add_query host, flag
    socket.send request.to_slice

    mismatch_retry.times do
      length, address = socket.receive buffer.to_slice
      length = 0_i32 unless length

      io = IO::Memory.new buffer.to_slice[0_i32, length]
      response = Packet::Response.from_io io, protocol
      io.close

      unless response
        next if socket.is_a? Network::UDPClient
        return
      end

      return response if request.transId == response.transId
    end
  end

  private def self.extract_canonical_name_ip_address(host : String, alias_server : AliasServer, list : Array(Socket::IPAddress))
    return unless _alias = alias_server[host]?

    loop do
      break unless _next = alias_server[_alias]?
      next _alias = _next if _next.is_a? String

      break _next.each { |item| list << item } if _next.is_a? Array(Socket::IPAddress)
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
          return unless _record.responds_to? :ipv6Address

          _ip_address = Socket::IPAddress.new _record.ipv6Address, port rescue nil
          next unless _ip_address
          next list << _ip_address if host == from
          alias_server[from] = Array(Socket::IPAddress).new unless alias_server[from]?

          if alias_list = alias_server[from]?
            alias_list << _ip_address if alias_list.is_a? Array(Socket::IPAddress)
          end
        when Record::A
          return unless _record.responds_to? :ipv4Address

          _ip_address = Socket::IPAddress.new _record.ipv4Address, port rescue nil
          next unless _ip_address
          next list << _ip_address if host == from
          alias_server[from] = Array(Socket::IPAddress).new unless alias_server[from]?

          if alias_list = alias_server[from]?
            alias_list << _ip_address if alias_list.is_a? Array(Socket::IPAddress)
          end
        when Record::CNAME
          return unless _record.responds_to? :canonicalName

          alias_server[from] = _record.canonicalName
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

  def self.getaddrinfo!(host : String, port : Int32, resolver : Resolver) : Tuple(Fetch, Socket::IPAddress)
    method, list = getaddrinfo_all host, port, resolver
    raise Socket::Error.new "Invalid host address" if list.empty?
    return Tuple.new method, list.first if 1_i32 == list.size || resolver.option.retry.nil?

    ip_address = TCPSocket.try_connect_ip_address list, resolver.option.retry
    raise Socket::Error.new "IP address cannot connect" unless ip_address

    ip_cache = resolver.ip_cache
    ip_cache.try &.set host, ip_address

    Tuple.new method, ip_address
  end

  def self.get_tcp_socket!(host : String, port : Int32, resolver : Resolver, connect_timeout : Int | Float? = nil) : ::TCPSocket
    method, list = getaddrinfo_all host, port, resolver
    raise Socket::Error.new "Invalid host address" if list.empty?

    if 1_i32 == list.size || resolver.option.retry.nil?
      return ::TCPSocket.new list.first.address, list.first.port, connect_timeout: connect_timeout || 5_i32
    end

    choose = TCPSocket.choose_ip_address list, resolver.option.retry
    raise Socket::Error.new "IP address cannot connect" unless choose

    socket, ip_address = choose
    ip_cache = resolver.ip_cache
    ip_cache.try &.set host, ip_address

    socket
  end

  def self.get_udp_socket!(host : String, port : Int32, resolver : Resolver) : ::UDPSocket
    method, list = getaddrinfo_all host, port, resolver
    raise Socket::Error.new "Invalid host address" if list.empty?

    ip_cache = resolver.ip_cache
    ip_cache.try &.set host, list.first

    socket = UDPSocket.new list.first.family
    socket.connect list.first

    socket
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress? = nil,
                           dnsServer : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32),
                           protocol : Protocol = Protocol::UDP,
                           &block : Tuple(Fetch, Array(Socket::IPAddress)) ->)
    yield getaddrinfo_all host, port, ip_cache, [Tuple.new dnsServer, protocol]
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress? = nil,
                           dnsServer : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32),
                           protocol : Protocol = Protocol::UDP) : Tuple(Fetch, Array(Socket::IPAddress))
    getaddrinfo_all host, port, ip_cache, [Tuple.new dnsServer, protocol]
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress?,
                           dnsServers : Array(Tuple(Socket::IPAddress, Protocol)),
                           &block : Tuple(Fetch, Array(Socket::IPAddress)) ->)
    yield getaddrinfo_all host, port, ip_cache, dnsServers
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress?,
                           dnsServers : Array(Tuple(Socket::IPAddress, Protocol))) : Tuple(Fetch, Array(Socket::IPAddress))
    resolver = new dnsServers
    resolver.ip_cache = ip_cache if ip_cache

    getaddrinfo_all host, port, resolver
  end

  def self.getaddrinfo_all(host : String, port : Int32, resolver : Resolver,
                           &block : Tuple(Fetch, Array(Socket::IPAddress)) ->)
    yield getaddrinfo_all host, port, resolver
  end

  def self.getaddrinfo_all(host : String, port : Int32, resolver : Resolver) : Tuple(Fetch, Array(Socket::IPAddress))
    host = resolver.mapping_host host
    specify = resolver.specify_dns_server host, port

    list = [] of Socket::IPAddress
    list << Socket::IPAddress.new host, port rescue nil
    return Tuple.new Fetch::Local, list unless list.empty?

    from_ip_cache = fetch_ip_cache host, port, resolver.ip_cache
    return Tuple.new Fetch::Cache, from_ip_cache unless from_ip_cache.empty? if from_ip_cache

    record_flags = [RecordFlag::A]
    record_flags = IPAddressRecordFlags if resolver.option.addrinfo.withIpv6

    resolver.resolve_task specify, host, Tuple.new record_flags, true, ->(resolve_response : ResolveResponse) do
      extract_all_ip_address host, port, resolve_response, list
    end

    ip_cache = resolver.ip_cache
    ip_cache.try &.set host, list unless list.empty?

    Tuple.new Fetch::Remote, list
  end

  def mapping_host(host : String) : String
    return host if option.mapping.empty?

    option.mapping.each do |item|
      case {!!item.isRegex, !!item.isStrict}
      when {!!item.isRegex, false}
        from = item.from

        if item.isRegex
          from = Regex.new item.from
        end

        host = host.gsub from, item.to
      when {false, true}
        host = item.to if host == item.from
      end
    end

    host
  end

  def specify_dns_server(host : String, port : Int32? = 0_i32) : Array(Tuple(Socket::IPAddress, Protocol))?
    return if option.specify.empty?

    list = [] of Tuple(Socket::IPAddress, Protocol)
    address = String.build { |io| io << host << port }

    option.specify.each do |item|
      case {!!item.isRegex, !!item.isStrict}
      when {true, false}
        break list = item.through if address.match Regex.new item.from
      when {false, false}
        break list = item.through if address.includes? item.from
      when {false, true}
        _address = item.withPort ? address : host
        break list = item.through if _address.downcase == item.from.downcase
      end
    end

    return if list.empty?
    return list
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
    flags.each { |flag| expires << flag if _cache.expires? host, flag }

    expires
  end

  def fetch_cache(host, flags : Array(RecordFlag), resolve_response : ResolveResponse)
    flags = flags - cache_expires? host, flags
    fetch = [] of RecordFlag

    flags.each do |flag|
      next unless packet = fetch_raw_cache host, flag

      resolve_response << Tuple.new host, flag, packet
      fetch << flag
    end

    fetch
  end

  def resolve_task(specify : Array(Tuple(Socket::IPAddress, Protocol))?, host : String, task : ResolveTask)
    packets = [] of Tuple(String, RecordFlag, Packet::Response)
    flags, strict_answer, proc = task

    cache_fetch = fetch_cache host, flags, packets
    return proc.call packets if cache_fetch.size == flags.size

    flags = flags - cache_fetch
    ip_address = to_ip_address host

    flags.each do |flag|
      next if cache_fetch.includes? flag
      next if ip_address && IPAddressRecordFlags.includes? flag
      next unless packet = resolve_by_flag! specify, host, flag, strict_answer

      packets << Tuple.new host, flag, packet
      set_cache host, packet, flag
    end

    proc.call packets
  end

  def resolve(host, flag : RecordFlag, strict_answer : Bool = false, &callback : ResolveResponse ->)
    self.tasks = tasks.set host, Immutable::Map(String, ResolveTask).new unless tasks[host]?

    loop do
      _random = random.hex
      next if item = tasks[host][_random]?

      update = tasks[host].set random.hex, Tuple.new [flag], strict_answer, callback
      break self.tasks = tasks.set host, update
    end
  end

  def resolve(host, flags : Array(RecordFlag), strict_answer : Bool = false, &callback : ResolveResponse ->)
    self.tasks = tasks.set host, Immutable::Map(String, ResolveTask).new unless tasks[host]?

    loop do
      _random = random.hex
      next if item = tasks[host][_random]?

      update = tasks[host].set random.hex, Tuple.new flags, strict_answer, callback
      break self.tasks = tasks.set host, update
    end
  end

  private def handle_task(host : String, task : Immutable::Map(String, ResolveTask))
    channel = Channel(String).new

    host = mapping_host host
    _specify = specify_dns_server host

    task.each do |id, item|
      spawn do
        resolve_task _specify, host, item
      ensure
        channel.send id
      end

      if receive_id = channel.receive
        tasks[host]?.try { |_task| self.tasks = tasks.set host, _task.delete receive_id }
      end
    end
  end

  def run
    tasks.each { |host, task| handle_task host, task }
  end
end
