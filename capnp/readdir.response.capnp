@0xf2f589d21924da65;

struct ReaddirResponse {
  res       @0 :Int8;
  errno     @1 :Int8;
  entries   @2 :List(Entry);

  struct Entry {
    name      @0 :Text;
    ino       @1 :UInt64;
    mode      @2 :UInt32;    # st_mode
    size      @3 :UInt64;    # st_size
    mtime     @4 :UInt64;    # st_mtime (seconds)
    mtimeNsec @5 :UInt32;    # st_mtime (nanoseconds)
  }
}
