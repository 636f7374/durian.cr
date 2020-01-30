class String
  def self.bits_build(&block : String::Builder ->) : Int16?
    String.build { |io| yield io }.to_i16? 2_i32
  end
end
