module Durian::Packet
  enum QRFlag : UInt16
    Query    = 0_u16
    Response = 1_u16
  end

  enum OperationCode : UInt16
    StandardQuery = 0_u16
    InverseQuery  = 1_u16
    Status        = 2_u16
    Reserved      = 3_u16
    Notify        = 4_u16
    Update        = 5_u16
  end

  enum AuthoritativeAnswer : UInt16
    False = 0_u16
    True  = 1_u16
  end

  enum Truncated : UInt16
    False = 0_u16
    True  = 1_u16
  end

  enum RecursionDesired : UInt16
    False = 0_u16
    True  = 1_u16
  end

  enum RecursionAvailable : UInt16
    False = 0_u16
    True  = 1_u16
  end

  enum AuthenticatedData : UInt16
    False = 0_u16
    True  = 1_u16
  end

  enum CheckingDisabled : UInt16
    False = 0_u16
    True  = 1_u16
  end

  enum ResponseCode : UInt16
    NoError        =  0_u16
    FormatError    =  1_u16
    ServerFailure  =  2_u16
    NameError      =  3_u16
    NotImplemented =  4_u16
    Refused        =  5_u16
    YXDomain       =  6_u16
    YXRRSet        =  7_u16
    NXRRSet        =  8_u16
    NotAuth        =  9_u16
    NotZone        = 10_u16
  end
end
