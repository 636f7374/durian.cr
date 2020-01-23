abstract class Durian::Record
  property from : String?
  property cls : Cls
  property ttl : UInt32
  property flag : RecordFlag

  def initialize(@from : String? = nil, @cls : Cls = Cls::IN, @ttl : UInt32 = 0_u32)
    @flag = RecordFlag::ANY
  end
end

require "./record/*"
