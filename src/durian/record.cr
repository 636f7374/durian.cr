class Durian::Record
  enum ResourceFlag
    # Pseudo Record Types
    ANY  = 255_i32
    AXFR = 252_i32
    IXFR = 251_i32
    OPT  =  41_i32

    # Active Record Types
    A          =     1_i32
    AAAA       =    28_i32
    AFSDB      =    18_i32
    APL        =    42_i32
    CAA        =   257_i32
    CDNSKEY    =    60_i32
    CDS        =    59_i32
    CERT       =    37_i32
    CNAME      =     5_i32
    DHCID      =    49_i32
    DLV        = 32769_i32
    DNAME      =    39_i32
    DNSKEY     =    48_i32
    DS         =    43_i32
    HIP        =    55_i32
    IPSECKEY   =    25_i32
    KX         =    36_i32
    LOC        =    29_i32
    MX         =    15_i32
    NAPTR      =    35_i32
    NS         =     2_i32
    NSEC       =    47_i32
    NSEC3      =    50_i32
    NSEC3PARAM =    51_i32
    OPENPGPKEY =    61_i32
    PTR        =    12_i32
    RRSIG      =    46_i32
    RP         =    17_i32
    SIG        =    24_i32
    SOA        =     6_i32
    SRV        =    33_i32
    SSHFP      =    44_i32
    TA         = 32768_i32
    TKEY       =   249_i32
    TLSA       =    52_i32
    TSIG       =   250_i32
    TXT        =    16_i32
    URI        =   256_i32

    # Obsolete Record Types
    MD       =   3_i32
    MF       =   4_i32
    MAILA    = 254_i32
    MB       =   7_i32
    MG       =   8_i32
    MR       =   9_i32
    MINFO    =  14_i32
    MAILB    = 253_i32
    WKS      =  11_i32
    NB       =  32_i32
    NBSTAT   =  33_i32
    NULL     =  10_i32
    A6       =  38_i32
    NXT      =  30_i32
    KEY      =  25_i32
    HINFO    =  13_i32
    X25      =  19_i32
    ISDN     =  20_i32
    RT       =  21_i32
    NSAP     =  22_i32
    NSAP_PTR =  23_i32
    PX       =  26_i32
    EID      =  31_i32
    NIMLOC   =  32_i32
    ATMA     =  34_i32
    SINK     =  40_i32
    GPOS     =  27_i32
    UINFO    = 100_i32
    UID      = 101_i32
    GID      = 102_i32
    UNSPEC   = 103_i32
    SPF      =  99_i32
  end

  enum Cls
    IN = 1_i32
  end

  property cls : Cls
  property ttl : UInt32
  property from : String?

  def initialize(@cls : Cls = Cls::IN, @ttl : UInt32 = 0_u32, @from : String? = nil)
  end
end

require "./record/*"
