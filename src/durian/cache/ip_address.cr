class Durian::Cache
  class IPAddress
    property storage : Hash(String, Entry)
    property capacity : Int32
    property cleanInterval : Time::Span
    property recordExpires : Time::Span
    property cleanAt : Time
    property maximumCleanup : Int32
    property mutex : Mutex

    def initialize(@storage : Hash(String, Entry) = Hash(String, Entry).new, @capacity : Int32 = 256_i32,
                   @cleanInterval : Time::Span = 3600_i32.seconds, @recordExpires : Time::Span = 1800_i32.seconds)
      @cleanAt = Time.local
      @maximumCleanup = (capacity / 2_i32).to_i32
      @mutex = Mutex.new :unchecked
    end

    def refresh
      @cleanAt = Time.local
    end

    def full?
      capacity <= size
    end

    def clean_expired?
      (Time.local - cleanAt) > cleanInterval
    end

    def reset
      self.storage.clear
    end

    def []=(name, value : Socket::IPAddress)
      set name, value
    end

    def []=(name, value : Array(Socket::IPAddress))
      set name, value
    end

    def [](name : String)
      value = storage[name]

      if value
        value.refresh
        value.tap
      end

      value
    end

    def []?(name : String)
      value = storage[name]?

      if value
        value.refresh
        value.tap
      end

      value
    end

    def expired?(name : String)
      return unless entry = storage[name]?
      return true if entry.ipAddress.empty?

      (Time.local - entry.accessAt) > recordExpires
    end

    def get(name : String, port : Int32) : Array(Socket::IPAddress)?
      return unless entry = storage[name]?

      entry.refresh ensure entry.tap
      list = [] of Socket::IPAddress

      entry.ipAddress.each do |ip_address|
        list << Socket::IPAddress.new ip_address.address, port
      end

      return if list.empty?
      list
    end

    def get(name : String) : Array(Socket::IPAddress)?
      return unless entry = storage[name]?

      entry.refresh ensure entry.tap
      entry.ipAddress
    end

    def set(name : String, ip_address : Socket::IPAddress)
      set name, [ip_address]
    end

    def set(name : String, ip_address : Array(Socket::IPAddress))
      return if ip_address.empty?

      @mutex.synchronize do
        inactive_clean

        unless storage[name]?
          self.storage[name] = Entry.new ip_address

          return
        end

        return unless entry = storage[name]?

        entry.ipAddress = ip_address
        entry.refresh
      end
    end

    def size
      storage.size
    end

    def empty?
      storage.empty?
    end

    def inactive_clean
      case {full?, clean_expired?}
      when {true, false}
        clean_by_tap
        refresh
      when {true, true}
        clean_by_access_at
        refresh
      else
      end
    end

    {% for name in ["tap", "access_at"] %}
    private def clean_by_{{name.id}}
      {% if name.id == "access_at" %}
      	temporary = [] of Tuple(Time, String)
      {% elsif name.id == "tap" %}
      	temporary = [] of Tuple(Int32, String)
      {% end %}

      _maximum = maximumCleanup - 1_i32

      storage.each do |name, entry|
      	{% if name.id == "access_at" %}
          temporary << Tuple.new entry.accessAt, name
      	{% elsif name.id == "tap" %}
      	  temporary << Tuple.new entry.tapCount, name
      	{% end %}
      end

      _sort = temporary.sort do |x, y|
        x.first <=> y.first
      end

      _sort.each_with_index do |sort, index|
        break if index > _maximum
        self.storage.delete sort.last
      end

      temporary.clear ensure _sort.clear
    end
    {% end %}

    class Entry
      property ipAddress : Array(Socket::IPAddress)
      property accessAt : Time
      property tapCount : Int32

      def initialize(@ipAddress : Array(Socket::IPAddress))
        @accessAt = Time.local
        @tapCount = 0_i32
      end

      def tap
        @tapCount = tapCount + 1_i32
      end

      def refresh
        @accessAt = Time.local
      end
    end
  end
end
