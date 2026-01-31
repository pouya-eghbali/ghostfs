@0xd8f2a1b3c4e5f678;

# Combined open + read for small file optimization
# Reduces 2 round-trips to 1 for small file reads

struct OpenAndRead {
  ino   @0 :UInt64;
  size  @1 :UInt64;  # Max bytes to read
  off   @2 :Int64;   # Read offset (usually 0)
  fi    @3 :FuseFileInfo;

  struct FuseFileInfo {
    flags         @0  :Int64;
    writepage     @1  :UInt64;
    directIo      @2  :UInt64;
    keepCache     @3  :UInt64;
    flush         @4  :UInt64;
    nonseekable   @5  :UInt64;
    cacheReaddir  @6  :UInt64;
    padding       @7  :UInt64;
    fh            @8  :UInt64;
    lockOwner     @9  :UInt64;
    pollEvents    @10 :UInt32;
    noflush       @11 :UInt64;
  }
}
