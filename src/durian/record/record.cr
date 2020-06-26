abstract class Durian::Record
  property from : String?
  property cls : Cls
  property ttl : UInt32
  property flag : RecordFlag

  def initialize(@from : String? = nil, @cls : Cls = Cls::Internet, @ttl : UInt32 = 0_u32)
    @flag = RecordFlag::ANY
  end

  {% for name in ["answer", "authority", "additional"] %}
  def self.decode_{{name.id}}(resource_record : Record, io : IO, buffer : IO)
    {% begin %}
    case resource_record
      {% for flag in AvailableRecordFlag %}
    when Record::{{flag.upcase.id}}
        Record::{{flag.id}}.{{name.id}}_from_io? resource_record, io, buffer
      {% end %}
    else
    end
    {% end %}
  end
  {% end %}

  def self.new(flag : RecordFlag)
    {% begin %}
      case flag
      	 {% for name in AvailableRecordFlag %}
      when .{{name.downcase.id}}?
        Record::{{name.upcase.id}}.new
      {% end %}
      else
        raise UnknownFlag.new flag.to_s
      end
    {% end %}
  end
end
