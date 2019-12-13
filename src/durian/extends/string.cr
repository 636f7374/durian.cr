class String
  def self.bits_build(&block : String::Builder ->) : Int32?
    String.build { |io| yield io }.to_i? 2_i32
  end
end
