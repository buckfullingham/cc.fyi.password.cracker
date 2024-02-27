#include <catch2/catch_all.hpp>

#include "md5.hpp"

#include <fstream>

TEST_CASE("rfc reference tests") {
  auto md5 = [](std::string_view s) {
    cracker::md5::calculator c;
    auto md5 = c.end(s.data(), s.data() + s.size());
    return cracker::md5::to_string(md5);
  };

  CHECK(md5("") == "d41d8cd98f00b204e9800998ecf8427e");
  CHECK(md5("a") == "0cc175b9c0f1b6a831c399e269772661");
  CHECK(md5("abc") == "900150983cd24fb0d6963f7d28e17f72");
  CHECK(md5("message digest") == "f96b697d7cb7938d525a2f31aaf161d0");
  CHECK(md5("abcdefghijklmnopqrstuvwxyz") ==
        "c3fcd3d76192e4007dfb496cca67e13b");
  CHECK(md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") ==
        "d174ab98d277d9f5a5611c2c9f419d9f");
  CHECK(md5("1234567890123456789012345678901234567890"
            "1234567890123456789012345678901234567890") ==
        "57edf4a22be3c955ac49da2e2107b67a");
}
