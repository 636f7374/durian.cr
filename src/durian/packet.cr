module Durian::Packet
  enum QRFlag
    Query
    Response
  end

  enum OperationCode
    StandardQuery
    InverseQuery
    Status
    Reserved
    Notify
    Update
  end

  enum AuthoritativeAnswer
    False
    True
  end

  enum Truncated
    False
    True
  end

  enum RecursionDesired
    False
    True
  end

  enum RecursionAvailable
    False
    True
  end

  enum AuthenticatedData
    False
    True
  end

  enum CheckingDisabled
    False
    True
  end

  enum ResponseCode
    NoError
    FormatError
    ServerFailure
    NameError
    NotImplemented
    Refused
    YXDomain
    YXRRSet
    NXRRSet
    NotAuth
    NotZone
  end
end

require "./packet/*"
