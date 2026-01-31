@0xe9f3b2c4d5a6e789;

struct OpenAndReadResponse {
  res    @0 :Int64;   # Bytes read, or -1 on error
  errno  @1 :Int8;
  fh     @2 :UInt64;  # File handle from open
  buf    @3 :Data;    # Read data
}
