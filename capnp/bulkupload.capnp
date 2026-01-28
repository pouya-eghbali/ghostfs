@0xf3c4d5e6a7b8c9d1;

struct BulkUpload {
  path     @0 :Text;
  buf      @1 :Data;
  offset   @2 :Int64;
  truncate @3 :Bool;
  mode     @4 :UInt32;
}
