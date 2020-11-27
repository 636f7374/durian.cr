class Durian::Cache
  class Record
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
      @cleanAt = Time.local
    end

    def full?
      capacity <= self.size
    end

    def clean_expired?
      timing = Time.local - cleanAt
      timing > cleanInterval
    end

    def clear
      @mutex.synchronize { self.storage.clear }
    end

    def []=(domain, value : Entry)
      set domain, value
    end

    def [](domain : String)
      @mutex.synchronize do
        return unless entry = storage[domain]

        entry.refresh_update_at
        entry.tap

        entry
      end
    end

    def []?(domain : String)
      @mutex.synchronize do
        return unless entry = storage[domain]?

        entry.refresh_update_at
        entry.tap

        entry
      end
    end

    def expired?(domain, flag : RecordFlag)
      @mutex.synchronize do
        return unless entry = storage[domain]?
        return unless updated_at = entry.update_at? flag

        timing = Time.local - updated_at
        timing > recordExpires
      end
    end

    def get(domain, flag : RecordFlag) : Array(Packet)?
      @mutex.synchronize do
        return unless entry = storage[domain]?
        return unless _record = entry.record? flag

        entry.refresh_access_at
        entry.tap
        _record.packets
      end
    end

    def set(domain : String, packets : Array(Packet), flag : RecordFlag)
      inactive_clean

      @mutex.synchronize do
        self.storage[domain] = Entry.new unless storage[domain]?
        return unless entry = storage[domain]?

        set entry, packets, flag
      end
    end

    private def set(entry : Entry, packets : Array(Packet), flag : RecordFlag)
      return unless item = entry.force_fetch flag

      item.packets = packets
      item.refresh_update_at
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
      property accessAt : Time
      property tapCount : Atomic(Int64)
      property a : PacketList?
      property aaaa : PacketList?
      property ns : PacketList?
      property ptr : PacketList?
      property cname : PacketList?
      property soa : PacketList?
      property txt : PacketList?
      property mx : PacketList?
      property dname : PacketList?
      property srv : PacketList?

      def initialize(@accessAt : Time = Time.local, @tapCount : Atomic(Int64) = Atomic(Int64).new 0_i64)
        @a = nil
        @aaaa = nil
        @ns = nil
        @ptr = nil
        @cname = nil
        @soa = nil
        @txt = nil
        @mx = nil
        @dname = nil
        @srv = nil
      end

      def tap
        tapCount.add 1_i64
      end

      def refresh_access_at
        @accessAt = Time.local
      end

      {% for name in AvailableRecordFlag %}
      def create_{{name.downcase.id}}
        self.{{name.downcase.id}} = PacketList.new
      end
      {% end %}

      def record?(flag : RecordFlag)
        {% begin %}
        case flag
          {% for name in AvailableRecordFlag %}
        when .{{name.downcase.id}}?
          {{name.downcase.id}}  
          {% end %}
        else
        end
      {% end %}
      end

      def create(flag : RecordFlag)
        {% begin %}
        case flag
          {% for name in AvailableRecordFlag %}
        when .{{name.downcase.id}}?
          create_{{name.downcase.id}} 
          {% end %}
        else
        end
      {% end %}
      end

      def update_at?(flag : RecordFlag)
        return unless _record = record? flag

        _record.updateAt
      end

      def force_fetch(flag : RecordFlag)
        create flag unless record? flag

        record? flag
      end

      class PacketList
        property packets : Array(Packet)?
        property updateAt : Time

        def initialize(@packets : Array(Packet)? = nil, @updateAt : Time = Time.local)
        end

        def self.new(packet : Packet? = nil, updateAt : Time = Time.local)
          new [packet], updateAt
        end

        def refresh_update_at
          @updateAt = Time.local
        end
      end
    end
  end
end
