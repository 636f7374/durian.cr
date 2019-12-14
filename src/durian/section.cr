module Durian::Section
  {% for name in ["answer", "authority", "additional"] %}
  def self.decode_record_{{name.id}}(resource_record : Record, io : IO, buffer : IO)
    {% begin %}
    case resource_record
      {% for record_type in RecordType %}
    when Record::{{record_type.upcase.id}}
        Record::{{record_type.id}}.{{name.id}}_from_io? resource_record, io, buffer
      {% end %}
    end
    {% end %}
  end
  {% end %}

  def self.new_resource_record(flag : RecordFlag)
    {% begin %}
      case flag
      	 {% for name in RecordType %}
      when .{{name.downcase.id}}?
        Record::{{name.upcase.id}}.new
      {% end %}
      else
        raise UnknownFlag.new flag.to_s
      end
    {% end %}
  end

  def self.decode_resource_pointer(io : IO, buffer : IO)
    pointer = uninitialized UInt8[2_i32]
    pointer_flag = io.read pointer.to_slice

    if 2_i32 != pointer_flag
      raise MalformedPacket.new "Expecting two bytes"
    end

    slice = pointer.to_slice

    if slice[0_i32] != 0b11000000
      raise MalformedPacket.new "Invalid pointer"
    end

    buffer.write slice
    Durian.decode_address_by_pointer buffer, slice[1_i32]
  end
end

require "./section/*"
