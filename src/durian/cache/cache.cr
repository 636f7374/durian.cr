class Durian::Cache
  property collects : Immutable::Map(String, RecordKind)
  property capacity : Int32
  property cleanInterval : Time::Span
  property recordExpires : Time::Span
  property cleanAt : Time
  property maximumCleanup : Int32

  def initialize(@collects : Immutable::Map(String, RecordKind) = Immutable::Map(String, RecordKind).new, @capacity : Int32 = 256_i32,
                 @cleanInterval : Time::Span = 3600_i32.seconds, @recordExpires : Time::Span = 1800_i32.seconds)
    @cleanAt = Time.local
    @maximumCleanup = (capacity / 2_i32).to_i32
  end

  def insert(name : String)
    insert = collects.set name, RecordKind.new
    @collects = insert
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
    @collects = collects.clear
  end

  def []=(name, value : RecordKind)
    set name, value
  end

  def [](name : String)
    value = collects[name]

    if value
      value.refresh
      value.tap
    end

    value
  end

  def []?(name : String)
    value = collects[name]?

    if value
      value.refresh
      value.tap
    end

    value
  end

  def expired?(name, flag : RecordFlag)
    return unless kind = collects[name]?
    return unless updated_at = kind.update_at? flag

    (Time.local - updated_at) > recordExpires
  end

  def get(name, flag : RecordFlag)
    return unless kind = collects[name]?
    return unless _record = kind.record? flag

    kind.refresh ensure kind.tap
    _record.packet
  end

  def set(name : String, packet : Packet::Response, flag : RecordFlag)
    inactive_clean

    insert name unless collects[name]?
    return unless _collects = collects
    return unless kind = _collects[name]?

    set kind, packet, flag
    @collects = _collects
  end

  private def set(kind : RecordKind, packet : Packet::Response, flag : RecordFlag)
    return unless item = kind.force_fetch flag

    item.packet = packet
    item.refresh
  end

  def size
    collects.size
  end

  def empty?
    collects.empty?
  end

  def inactive_clean
    case {full?, clean_expired?}
    when {true, false}
      clean_by_tap
      refresh
    when {true, true}
      clean_by_access_at
      refresh
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
      _collects = collects


      collects.each do |name, item|
      	{% if name.id == "access_at" %}
          temporary << Tuple.new item.accessAt, name
      	{% elsif name.id == "tap" %}
      	  temporary << Tuple.new item.tapCount, name
      	{% end %}
      end

      _sort = temporary.sort do |x, y|
        x.first <=> y.first
      end

      _sort.each_with_index do |sort, index|
        break if index > _maximum
       _collects = _collects.delete sort.last
      end

      @collects = _collects
      temporary.clear ensure _sort.clear
    end
    {% end %}

  class RecordKind
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

    {% for name in RecordType %}
      def create_{{name.downcase.id}}
      	self.{{name.downcase.id}} = Entry.new
      end
      {% end %}

    def record?(flag : RecordFlag)
      {% begin %}
        case flag
          {% for name in RecordType %}
        when .{{name.downcase.id}}?
          {{name.downcase.id}}	
          {% end %}
        end
        {% end %}
    end

    def create(flag : RecordFlag)
      {% begin %}
        case flag
          {% for name in RecordType %}
        when .{{name.downcase.id}}?
          create_{{name.downcase.id}}	
          {% end %}
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
      property packet : Packet::Response?
      property updateAt : Time

      def initialize(@packet : Packet::Response? = nil, @updateAt : Time = Time.local)
      end

      def refresh
        @updateAt = Time.local
      end
    end
  end
end
