using Go = import "/go.capnp";

@0xfc934851acf345ab;

$Go.package("logformat");
$Go.import("arvancloud/redins/handler/logformat");

struct RequestLog {
  timestamp @0 :UInt64;
  uuid @1 :Text;
  record @2 :Text;
  type @3 :Text;
  ip @4 :Text;
  country @5 :Text;
  asn @6 :UInt32;
  responsecode @7 :UInt16;
  processtime @8 :UInt16;
  cache @9 :Text;
}