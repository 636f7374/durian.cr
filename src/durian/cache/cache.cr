class Durian::Cache
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

  def []=(name, value : Entry)
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

  def expired?(name, flag : RecordFlag)
    return unless entry = storage[name]?
    return unless updated_at = entry.update_at? flag

    (Time.local - updated_at) > recordExpires
  end

  def get(name, flag : RecordFlag)
    return unless entry = storage[name]?
    return unless _record = entry.record? flag

    entry.refresh ensure entry.tap
    _record.packet
  end

  def set(name : String, packet : Packet, flag : RecordFlag)
    @mutex.synchronize do
      inactive_clean

      self.storage[name] = Entry.new unless storage[name]?
      return unless entry = storage[name]?

      set entry, packet, flag
    end
  end

  private def set(entry : Entry, packet : Packet, flag : RecordFlag)
    return unless item = entry.force_fetch flag

    item.packet = packet
    item.refresh
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
    property accessAt : Time
    property tapCount : Int32
    property a : Entry?
    property aaaa : Entry?
    property ns : Entry?
    property ptr : Entry?
    property cname : Entry?
    property soa : Entry?
    property txt : Entry?
    property mx : Entry?
    property dname : Entry?
    property srv : Entry?

    def initialize(@accessAt : Time = Time.local, @tapCount : Int32 = 0_i32)
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
      @tapCount = tapCount + 1_i32
    end

    def refresh
      @accessAt = Time.local
    end

    {% for name in AvailableRecordFlag %}
      def create_{{name.downcase.id}}
      	self.{{name.downcase.id}} = Entry.new
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

    class Entry
      property packet : Packet?
      property updateAt : Time

      def initialize(@packet : Packet? = nil, @updateAt : Time = Time.local)
      end

      def refresh
        @updateAt = Time.local
      end
    end
  end
end
