class Durian::Resolver
  struct FetchList
    getter type : Fetch
    getter list : Array(Socket::IPAddress)
    getter listHash : UInt64

    def initialize(@type : Fetch = Fetch::Local, @list : Array(Socket::IPAddress) = [] of Socket::IPAddress, @listHash : UInt64 = 0_u64)
    end

    def empty?
      list.empty?
    end

    def size
      list.size
    end

    def first
      list.first
    end

    def first?
      list.first?
    end

    def last
      list.last
    end

    def last?
      list.last?
    end
  end
end
