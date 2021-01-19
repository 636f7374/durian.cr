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

    def size
      @mutex.synchronize { storage.size }
    end

    def empty? : Bool
      @mutex.synchronize { storage.empty? }
    end

    def refresh_clean_at
      @mutex.synchronize { @cleanAt = Time.local }
    end

    def full?
      capacity <= self.size
    end

    def clean_expired?
      timing = Time.local - @mutex.synchronize { cleanAt }
      timing > cleanInterval
    end

    def clear
      @mutex.synchronize { self.storage.clear }
    end

    def []=(domain, ip_address : Socket::IPAddress)
      set domain, ip_address
    end

    def []=(domain, ip_address : Array(Socket::IPAddress))
      set domain, ip_address
    end

    def [](domain : String)
      @mutex.synchronize do
        return unless entry = storage[domain]

        entry.refresh_access_at
        entry.tap

        entry
      end
    end

    def []?(domain : String)
      @mutex.synchronize do
        return unless entry = storage[domain]?

        entry.refresh_access_at
        entry.tap

        entry
      end
    end

    def expired?(domain : String)
      @mutex.synchronize do
        return unless entry = storage[domain]?
        return true if entry.ipAddress.empty?

        timing = Time.local - entry.accessAt
        timing > recordExpires
      end
    end

    def get(domain : String, port : Int32) : Array(Socket::IPAddress)?
      @mutex.synchronize do
        return unless entry = storage[domain]?

        entry.refresh_access_at
        entry.tap

        list = [] of Socket::IPAddress

        entry.ipAddress.each do |ip_address|
          list << Socket::IPAddress.new ip_address.address, port
        end

        return if list.empty?
        list
      end
    end

    def get(domain : String) : Array(Socket::IPAddress)?
      @mutex.synchronize do
        return unless entry = storage[domain]?

        entry.refresh_access_at
        entry.tap
        entry.ipAddress
      end
    end

    def set(domain : String, ip_address : Socket::IPAddress)
      set domain, [ip_address]
    end

    def set(domain : String, ip_address : Array(Socket::IPAddress))
      return if ip_address.empty?
      inactive_clean

      @mutex.synchronize do
        unless self.storage[domain]?
          self.storage[domain] = Entry.new ip_address
        end

        return unless entry = storage[domain]?

        entry.ipAddress = ip_address
        entry.refresh_access_at
      end
    end

    def inactive_clean
      case {full?, clean_expired?}
      when {true, false}
        clean_by_tap
        refresh_clean_at
      when {true, true}
        clean_by_access_at
        refresh_clean_at
      else
      end
    end

    {% for name in ["tap", "access_at"] %}
    private def clean_by_{{name.id}}
      {% if name.id == "access_at" %}
      	temporary_list = [] of Tuple(Time, String)
      {% elsif name.id == "tap" %}
      	temporary_list = [] of Tuple(Int64, String)
      {% end %}

      _maximum = maximumCleanup - 1_i32

      @mutex.synchronize do
        storage.each do |domain, entry|
      	 {% if name.id == "access_at" %}
            temporary_list << Tuple.new entry.accessAt, domain
      	 {% elsif name.id == "tap" %}
      	    temporary_list << Tuple.new entry.tapCount.get, domain
      	 {% end %}
        end

        _sort = temporary_list.sort do |x, y|
          x.first <=> y.first
        end

        _sort.each_with_index do |sort, index|
          break if index > _maximum
          self.storage.delete sort.last
        end
      end
    end
    {% end %}

    class Entry
      property ipAddress : Array(Socket::IPAddress)
      property accessAt : Time
      property tapCount : Atomic(Int64)

      def initialize(@ipAddress : Array(Socket::IPAddress))
        @accessAt = Time.local
        @tapCount = Atomic(Int64).new 0_i64
      end

      def tap
        tapCount.add 1_i64
      end

      def refresh_access_at
        @accessAt = Time.local
      end
    end
  end
end
