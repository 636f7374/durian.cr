class Durian::PendingList
  property getaddrinfoList : Array(String)
  property getaddrinfoMutex : Mutex

  def initialize
    @getaddrinfoList = Array(String).new
    @getaddrinfoMutex = Mutex.new :unchecked
  end

  def <<(domain : String)
    getaddrinfoMutex.synchronize { getaddrinfoList << domain }
  end

  def delete(domain : String)
    getaddrinfoMutex.synchronize { getaddrinfoList.delete domain }
  end

  def includes?(domain : String) : Bool
    getaddrinfoMutex.synchronize { getaddrinfoList.includes? domain }
  end
end
