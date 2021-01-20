class Durian::Resolver
  IPAddressRecordFlags = [RecordFlag::A, RecordFlag::AAAA]

  alias ResolveResponse = Array(Tuple(String, RecordFlag, Array(Packet)))
  alias ResolveTask = Tuple(Array(RecordFlag), Bool, Proc(ResolveResponse, Nil))
  alias AliasServer = Hash(String, String | Array(Socket::IPAddress))

  property dnsServers : Array(Server)
  property tasks : Hash(String, Hash(String, ResolveTask))
  property option : Option
  property mutex : Mutex
  property getaddrinfoPendingList : PendingList

  def initialize(@dnsServers : Array(Server))
    @tasks = Hash(String, Hash(String, ResolveTask)).new
    @option = Option.new
    @mutex = Mutex.new :unchecked
    @getaddrinfoPendingList = PendingList.new
  end

  def self.new(dns_server : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32), protocol : Protocol = Protocol::UDP)
    new [Server.new dns_server, protocol]
  end

  def record_cache=(value : Cache::Record)
    @recordCache = value
  end

  def record_cache
    @recordCache
  end

  def ip_cache=(value : Cache::IPAddress)
    @ipCache = value
  end

  def ip_cache
    @ipCache
  end

  def coffee=(value : Coffee::Scanner)
    @coffee = value
  end

  def coffee
    @coffee
  end

  def query_record!(specify : Array(Server)?, host : String,
                    flag : RecordFlag, strict_answer : Bool = false) : Array(Packet)?
    servers = specify || dnsServers

    task_mutex = Mutex.new :unchecked
    response_packets_list = [] of Packet?

    servers.each do |server|
      spawn do
        socket = Network.create server, option.timeout rescue nil
        next task_mutex.synchronize { response_packets_list << nil } unless socket

        packet = query_record! socket, host, flag rescue nil

        unless packet
          socket.close
          next task_mutex.synchronize { response_packets_list << nil }
        end

        if strict_answer
          if packet.answerCount.zero? || packet.answers.empty?
            socket.close
            next task_mutex.synchronize { response_packets_list << nil }
          end

          include_flag = false
          packet.answers.each { |answer| break include_flag = true if answer.flag == flag }

          unless include_flag
            socket.close
            next task_mutex.synchronize { response_packets_list << nil }
          end
        end

        socket.close
        next task_mutex.synchronize { response_packets_list << packet }
      end
    end

    loop do
      next sleep 0.05_f32.seconds if response_packets_list.size != servers.size
      return task_mutex.synchronize { response_packets_list.compact }
    end
  end

  def get_socket_protocol(socket : IO) : Protocol?
    case socket
    when .is_a? TCPSocket
      Protocol::TCP
    when .is_a? UDPSocket
      Protocol::UDP
    when .is_a? OpenSSL::SSL::Socket::Client
      Protocol::TLS
    end
  end

  def mismatch_retry
    return 5_i32 unless retry = option.retry

    retry.mismatch
  end

  def query_record!(socket : IO?, host : String, flag : RecordFlag, strict_answer : Bool = false) : Packet?
    return unless socket
    return unless protocol = get_socket_protocol socket

    buffer = uninitialized UInt8[4096_i32]

    request = Packet.new protocol: protocol, qrFlag: Packet::QRFlag::Query
    request.add_query host, flag
    socket.write request.to_slice

    mismatch_retry.times do
      length = socket.read buffer.to_slice
      break if length.zero? && (protocol.tcp? || protocol.tls?)

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

  private def self.extract_all_ip_address(host : String, port : Int32, resolve_responses : ResolveResponse,
                                          list : Array(Socket::IPAddress))
    resolve_responses.each do |response|
      host, flag, packets = response

      packets.each do |packet|
        alias_server = AliasServer.new

        packet.answers.each do |answer|
          _record = answer.resourceRecord
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
  end

  def self.fetch_ip_cache(host : String, port : Int32, ip_cache : Cache::IPAddress?)
    return unless ip_cache
    return if ip_cache.expired? host

    ip_cache.get host, port
  end

  def self.getaddrinfo!(host : String, port : Int32, resolver : Resolver, try_connect : Bool = true) : Tuple(Fetch, Socket::IPAddress)
    fetch_list = getaddrinfo_all host, port, resolver
    raise Socket::Error.new "Invalid host address" if fetch_list.empty?

    return Tuple.new fetch_list.type, fetch_list.first if 1_i32 == fetch_list.size || resolver.option.retry.nil? || !try_connect

    ip_address = TCPSocket.try_connect_ip_address fetch_list.list, resolver.option.retry
    raise Socket::Error.new "IP address cannot connect" unless ip_address

    Tuple.new fetch_list.type, ip_address
  end

  def self.get_tcp_socket!(host : String, port : Int32, resolver : Resolver, connect_timeout : Int | Float? = nil) : ::TCPSocket
    fetch_list = getaddrinfo_all host, port, resolver
    raise Socket::Error.new "DNS query result IP is empty, or DNS query failed" if fetch_list.empty?

    if 1_i32 == fetch_list.size || resolver.option.retry.nil?
      return ::TCPSocket.new fetch_list.first.address, fetch_list.first.port, connect_timeout: connect_timeout || 5_i32
    end

    choose = TCPSocket.choose_socket fetch_list.list, resolver.option.retry

    unless choose
      if fetch_list.type.coffee?
        cache = resolver.try &.coffee.try &.cache
        cache.try &.clear if fetch_list.listHash == cache.try &.hash
      end

      raise Socket::Error.new "IP address cannot connect"
    end

    socket, ip_address = choose

    socket
  end

  def self.get_udp_socket!(host : String, port : Int32, resolver : Resolver) : ::UDPSocket
    fetch_list = getaddrinfo_all host, port, resolver
    raise Socket::Error.new "Invalid host address" if fetch_list.empty?

    socket = UDPSocket.new fetch_list.first.family
    socket.connect fetch_list.first

    socket
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress? = nil,
                           dns_server : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32),
                           protocol : Protocol = Protocol::UDP,
                           tls : Server::TransportLayerSecurity? = nil,
                           &block : FetchList ->)
    yield getaddrinfo_all host, port, ip_cache, [Server.new dns_server, protocol, tls]
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress? = nil,
                           dns_server : Socket::IPAddress = Socket::IPAddress.new("8.8.8.8", 53_i32),
                           protocol : Protocol = Protocol::UDP,
                           tls : Server::TransportLayerSecurity? = nil) : FetchList
    getaddrinfo_all host, port, ip_cache, [Server.new dns_server, protocol, tls]
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress?,
                           dns_server : Array(Server), &block : FetchList ->)
    yield getaddrinfo_all host, port, ip_cache, dns_server
  end

  def self.getaddrinfo_all(host : String, port : Int32, ip_cache : Cache::IPAddress?,
                           dns_server : Array(Server)) : FetchList
    resolver = new dns_server
    resolver.ip_cache = ip_cache if ip_cache

    getaddrinfo_all host, port, resolver
  end

  def self.getaddrinfo_all(host : String, port : Int32, resolver : Resolver,
                           &block : Tuple(Fetch, Array(Socket::IPAddress)) ->)
    yield getaddrinfo_all host, port, resolver
  end

  def self.from_cloudflare(host : String, port : Int32, resolver : Resolver) : Tuple(UInt64, Array(Socket::IPAddress))?
    return unless resolver.cloudflare? host, port
    return unless cache = resolver.try &.coffee.try &.cache
    return unless list = cache.to_ip_address port
    return if list.empty?

    Tuple.new cache.hash, list
  end

  def self.getaddrinfo_all(host : String, port : Int32, resolver : Resolver) : FetchList
    # Mapping
    _mapping = resolver.mapping? host, port

    # Fetch data from Mapping local
    local = resolver.mapping_local? _mapping, port if _mapping
    return FetchList.new type: Fetch::Local, list: local if local

    # Test if it is an IP address
    _address = resolver.mapping_to? _mapping, port if _mapping
    host, port = _address if _address
    ip_address = Socket::IPAddress.new host, port rescue nil
    return FetchList.new type: Fetch::Local, list: [ip_address] if ip_address

    # Fetch data from Cloudflare
    _from_cloudflare = from_cloudflare host, port, resolver

    if _from_cloudflare
      hash, list = _from_cloudflare
      return FetchList.new type: Fetch::Coffee, list: list, listHash: hash
    end

    # Set Pending
    if resolver.ip_cache
      resolver.pending_getaddrinfo_fetch host, port, resolver

      # Fetch data from IP cache
      from_ip_cache = fetch_ip_cache host, port, resolver.ip_cache

      if from_ip_cache
        unless from_ip_cache.empty?
          resolver.getaddrinfoPendingList.delete host
          return FetchList.new type: Fetch::Cache, list: from_ip_cache
        end
      end
    end

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

    list = list.uniq
    resolver.ip_cache.try &.set host, list unless list.empty?

    # Remove Pending
    resolver.getaddrinfoPendingList.delete host if resolver.ip_cache

    FetchList.new type: Fetch::Remote, list: list
  end

  def pending_getaddrinfo_fetch(host : String, port : Int32, resolver : Resolver) : Nil
    from_ip_cache = Resolver.fetch_ip_cache host, port, resolver.ip_cache
    return if from_ip_cache

    if getaddrinfoPendingList.includes? host
      before_time = Time.local

      loop do
        break if 5_i32.seconds <= (Time.local - before_time)
        break unless getaddrinfoPendingList.includes? host

        sleep 0.05_f32
      end
    end

    getaddrinfoPendingList << host unless getaddrinfoPendingList.includes? host
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

  def set_record_cache(host, packets : Array(Packet), flag : RecordFlag)
    record_cache.try &.set host, packets, flag
  end

  def set_record_cache(host, packet : Packet, flag : RecordFlag)
    record_cache.try &.set host, [packet], flag
  end

  def fetch_record_cache(host, flag : RecordFlag)
    record_cache.try &.get host, flag
  end

  def cache_expires?(host, flags : Array(RecordFlag))
    expires = [] of RecordFlag
    return expires unless _cache = record_cache

    flags.each { |flag| expires << flag if _cache.expired? host, flag }

    expires
  end

  def fetch_cache(host, flags : Array(RecordFlag), resolve_response : ResolveResponse)
    flags = flags - cache_expires? host, flags
    fetch = [] of RecordFlag

    flags.each do |flag|
      next unless packet = fetch_record_cache host, flag

      resolve_response << Tuple.new host, flag, packet
      fetch << flag
    end

    fetch
  end

  def resolve_task(specify : Array(Server)?, host : String, task : ResolveTask)
    response = [] of Tuple(String, RecordFlag, Array(Packet))
    flags, strict_answer, proc = task

    cache_fetch = fetch_cache host, flags, response
    return proc.call response if cache_fetch.size == flags.size

    flags = flags - cache_fetch
    ip_address = to_ip_address host

    flags.each do |flag|
      next if cache_fetch.includes? flag
      next if ip_address && IPAddressRecordFlags.includes? flag
      next unless resolve_packets = query_record! specify, host, flag, strict_answer

      response << Tuple.new host, flag, resolve_packets
      set_record_cache host, resolve_packets, flag
    end

    proc.call response
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
    _host = host.dup
    _mapping = mapping? _host
    _to = mapping_to? _mapping if _mapping
    _host = _to.first if _to

    _specify = specify? _host
    _throughs = _specify.throughs if _specify

    task.each do |id, item|
      spawn do
        resolve_task _throughs, _host, item

        @mutex.synchronize do
          tasks[_host]?.try { |_task| _task.delete id }
          tasks.delete _host if tasks[_host].empty?
        end
      end
    end
  end

  def run
    tasks.each do |host, task|
      handle_task host, task
    end

    loop do
      tasks_size = @mutex.synchronize { tasks.size }
      break if tasks_size.zero?

      sleep 0.05_f32
    end
  end
end
