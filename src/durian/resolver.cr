class Durian::Resolver
  IPAddressRecordFlags = [RecordFlag::A, RecordFlag::AAAA]

  alias ResolveResponse = Array(Tuple(String, RecordFlag, Packet))
  alias ResolveTask = Tuple(Array(RecordFlag), Bool, Proc(ResolveResponse, Nil))
  alias AliasServer = Hash(String, String | Array(Socket::IPAddress))

  property dnsServers : Array(Tuple(Socket::IPAddress, Protocol))
  property tasks : Hash(String, Hash(String, ResolveTask))
  property option : Option
  property mutex : Mutex

  def initialize(@dnsServers : Array(Tuple(Socket::IPAddress, Protocol)))
    @tasks = Hash(String, Hash(String, ResolveTask)).new
    @option = Option.new
    @mutex = Mutex.new :unchecked
  end

  def self.new(dns_server : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32), protocol : Protocol = Protocol::UDP)
    new [Tuple.new dns_server, protocol]
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

  def coffee=(value : Coffee::Scanner)
    @coffee = value
  end

  def coffee
    @coffee
  end

  def resolve_by_flag!(specify : Array(Tuple(Socket::IPAddress, Protocol))?, host : String,
                       flag : RecordFlag, strict_answer : Bool = false) : Packet?
    servers = specify || dnsServers

    servers.each do |server|
      socket = Network.create server, option.timeout rescue nil
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

  def get_socket_protocol(socket : IPSocket)
    socket.is_a?(TCPSocket) ? Protocol::TCP : Protocol::UDP
  end

  def mismatch_retry
    return 5_i32 unless retry = option.retry

    retry.mismatch
  end

  def resolve_by_flag!(socket : IPSocket, host : String, flag : RecordFlag, strict_answer : Bool = false) : Packet?
    buffer = uninitialized UInt8[4096_i32]
    protocol = get_socket_protocol socket

    request = Packet.new protocol: protocol, qrFlag: Packet::QRFlag::Query
    request.add_query host, flag
    socket.write request.to_slice

    mismatch_retry.times do
      length = socket.read buffer.to_slice
      break if length.zero? && protocol.tcp?

      io = IO::Memory.new buffer.to_slice[0_i32, length]
      response = Packet.from_io protocol: protocol, io: io

      unless response
        next if protocol.udp?

        break
      end

      break unless qr_flag = response.qrFlag
      break unless qr_flag.response?

      break response if request.transId == response.transId
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
          return unless ipv6_address = _record.ipv6Address
          ipv6_address = Socket::IPAddress.new ipv6_address.address, port

          next list << ipv6_address if host == from
          alias_server[from] = Array(Socket::IPAddress).new unless alias_server[from]?

          next unless alias_list = alias_server[from]?
          alias_list << ipv6_address if alias_list.is_a? Array(Socket::IPAddress)
        when Record::A
          return unless _record.responds_to? :ipv4Address
          return unless ipv4_address = _record.ipv4Address
          ipv4_address = Socket::IPAddress.new ipv4_address.address, port

          next list << ipv4_address if host == from
          alias_server[from] = Array(Socket::IPAddress).new unless alias_server[from]?

          next unless alias_list = alias_server[from]?
          alias_list << ipv4_address if alias_list.is_a? Array(Socket::IPAddress)
        when Record::CNAME
          return unless _record.responds_to? :canonicalName

          alias_server[from] = _record.canonicalName
        else
        end
      end

      extract_canonical_name_ip_address host, alias_server, list
      alias_server.clear
    end
  end

  def self.fetch_ip_cache(host : String, port : Int32, ip_cache : Cache::IPAddress?)
    return unless ip_cache
    return if ip_cache.expired? host

    ip_cache.get host, port
  end

  def self.getaddrinfo!(host : String, port : Int32, resolver : Resolver) : Tuple(Fetch, Socket::IPAddress)
    method, list = getaddrinfo_all host, port, resolver
    raise Socket::Error.new "Invalid host address" if list.empty?

    return Tuple.new method, list.first if 1_i32 == list.size || resolver.option.retry.nil?

    ip_address = TCPSocket.try_connect_ip_address list, resolver.option.retry
    raise Socket::Error.new "IP address cannot connect" unless ip_address

    Tuple.new method, ip_address
  end

  def self.get_tcp_socket!(host : String, port : Int32, resolver : Resolver, connect_timeout : Int | Float? = nil) : ::TCPSocket
    method, list = getaddrinfo_all host, port, resolver
    raise Socket::Error.new "Invalid host address" if list.empty?

    if 1_i32 == list.size || resolver.option.retry.nil?
      return ::TCPSocket.new list.first.address, list.first.port, connect_timeout: connect_timeout || 5_i32
    end

    choose = TCPSocket.choose_socket list, resolver.option.retry
    raise Socket::Error.new "IP address cannot connect" unless choose

    socket, ip_address = choose

    socket
  end

  def self.get_udp_socket!(host : String, port : Int32, resolver : Resolver) : ::UDPSocket
    method, list = getaddrinfo_all host, port, resolver
    raise Socket::Error.new "Invalid host address" if list.empty?

    socket = UDPSocket.new list.first.family
    socket.connect list.first

    socket
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress? = nil,
                           dns_server : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32),
                           protocol : Protocol = Protocol::UDP,
                           &block : Tuple(Fetch, Array(Socket::IPAddress)) ->)
    yield getaddrinfo_all host, port, ip_cache, [Tuple.new dns_server, protocol]
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress? = nil,
                           dns_server : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32),
                           protocol : Protocol = Protocol::UDP) : Tuple(Fetch, Array(Socket::IPAddress))
    getaddrinfo_all host, port, ip_cache, [Tuple.new dns_server, protocol]
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress?,
                           dns_server : Array(Tuple(Socket::IPAddress, Protocol)),
                           &block : Tuple(Fetch, Array(Socket::IPAddress)) ->)
    yield getaddrinfo_all host, port, ip_cache, dns_server
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress?,
                           dns_server : Array(Tuple(Socket::IPAddress, Protocol))) : Tuple(Fetch, Array(Socket::IPAddress))
    resolver = new dns_server
    resolver.ip_cache = ip_cache if ip_cache

    getaddrinfo_all host, port, resolver
  end

  def self.getaddrinfo_all(host : String, port : Int32, resolver : Resolver,
                           &block : Tuple(Fetch, Array(Socket::IPAddress)) ->)
    yield getaddrinfo_all host, port, resolver
  end

  def self.from_cloudflare(host : String, port : Int32, resolver : Resolver) : Array(Socket::IPAddress)?
    return unless resolver.cloudflare? host, port
    return unless cache = resolver.try &.coffee.try &.cache
    return unless list = cache.to_ip_address port
    return if list.empty?

    list
  end

  def self.getaddrinfo_all(host : String, port : Int32, resolver : Resolver) : Tuple(Fetch, Array(Socket::IPAddress))
    # Fetch data from Cloudflare
    _from_cloudflare = from_cloudflare host, port, resolver
    return Tuple.new Fetch::Coffee, _from_cloudflare if _from_cloudflare

    # Mapping
    _mapping = resolver.mapping? host, port

    # Fetch data from Mapping local
    local = resolver.mapping_local? _mapping, port if _mapping
    return Tuple.new Fetch::Local, local if local

    # Test if it is an IP address
    _address = resolver.mapping_to? _mapping, port if _mapping
    host, port = _address if _address
    ip_address = Socket::IPAddress.new host, port rescue nil
    return Tuple.new Fetch::Local, [ip_address] if ip_address

    # Fetch data from IP cache
    from_ip_cache = fetch_ip_cache host, port, resolver.ip_cache
    return Tuple.new Fetch::Cache, from_ip_cache unless from_ip_cache.empty? if from_ip_cache

    # Set fetch type
    record_flags = [RecordFlag::A]
    record_flags = IPAddressRecordFlags if resolver.option.addrinfo.withIpv6

    # Switch to a custom DNS server
    _specify = resolver.specify? host, port
    _throughs = _specify.throughs if _specify

    list = [] of Socket::IPAddress

    resolver.resolve_task _throughs, host, Tuple.new record_flags, true, ->(resolve_response : ResolveResponse) do
      extract_all_ip_address host, port, resolve_response, list
    end

    resolver.ip_cache.try &.set host, list unless list.empty?
    Tuple.new Fetch::Remote, list
  end

  {% for name in ["mapping", "specify", "cloudflare"] %}
  def {{name.id}}?(host : String, port : Int32? = 0_i32) : Option::{{name.capitalize.id}}?
    return if option.{{name.id}}.empty?

    list = [] of Option::{{name.capitalize.id}}
    address = String.build { |io| io << host << ":" << port }

    option.{{name.id}}.each do |item|
      _address = item.withPort ? address : host

      case {!!item.isRegex, !!item.isStrict}
      when {true, false}
        break list << item if _address.match Regex.new item.from
      when {false, false}
        break list << item if _address.includes? item.from
      when {false, true}
        break list << item if _address.downcase == item.from.downcase
      else
      end
    end

    return if list.empty?
    list.first
  end
  {% end %}

  def mapping_to?(item, port : Int32 = 0_i32) : Tuple(String, Int32)?
    return unless to = item.to

    case !!item.withPort
    when true
      _to = to.rpartition ":"
      return Tuple.new to, port unless _port = _to.last.to_i?

      Tuple.new _to.first, _port
    when false
      Tuple.new to, port
    end
  end

  def mapping_local?(item, port : Int32 = 0_i32) : Array(Socket::IPAddress)?
    return unless local = item.local
    return if local.empty?

    unless !!item.withPort
      return local.map { |_local| Socket::IPAddress.new _local.address, port }
    end

    local
  end

  def to_ip_address(host : String)
    Socket::IPAddress.new host, 0_i32 rescue nil
  end

  def set_cache(host, packet : Packet, flag : RecordFlag)
    cache.try &.set host, packet, flag
  end

  def fetch_raw_cache(host, flag : RecordFlag)
    cache.try &.get host, flag
  end

  def cache_expires?(host, flags : Array(RecordFlag))
    expires = [] of RecordFlag
    return expires unless _cache = cache

    flags.each { |flag| expires << flag if _cache.expired? host, flag }

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
    packets = [] of Tuple(String, RecordFlag, Packet)
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
    @mutex.synchronize do
      tasks[host] = Hash(String, ResolveTask).new unless tasks[host]?

      loop do
        _random = Random.new.hex
        next if item = tasks[host][_random]?

        break tasks[host][_random] = Tuple.new [flag], strict_answer, callback
      end
    end
  end

  def resolve(host, flags : Array(RecordFlag), strict_answer : Bool = false, &callback : ResolveResponse ->)
    @mutex.synchronize do
      tasks[host] = Hash(String, ResolveTask).new unless tasks[host]?

      loop do
        _random = Random.new.hex
        next if item = tasks[host][_random]?

        break tasks[host][_random] = Tuple.new flags, strict_answer, callback
      end
    end
  end

  private def handle_task(host : String, task : Hash(String, ResolveTask))
    channel = Channel(String).new

    _host = host.dup
    _mapping = mapping? _host
    _to = mapping_to? _mapping if _mapping
    _host = _to.first if _to

    _specify = specify? _host
    _throughs = _specify.throughs if _specify

    task.each do |id, item|
      spawn do
        resolve_task _throughs, _host, item
      ensure
        channel.send id
      end
    end

    if task_id = channel.receive
      @mutex.synchronize do
        tasks[host]?.try { |_task| _task.delete task_id }
        tasks.delete host if tasks[host].empty?
      end
    end
  end

  def run
    tasks.each { |host, task| handle_task host, task }
  end
end
