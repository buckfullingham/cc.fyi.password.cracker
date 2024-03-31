#include <catch2/catch_all.hpp>

#include "settings.hpp"

namespace ns = cracker;

namespace {

std::string make_alphabet(const std::regex &regex) {
  std::string result;
  for (int i = 0; i < 128; ++i) {
    const char c = static_cast<char>(i);
    char str[2]{c, '\0'};
    if (std::regex_match(str, regex))
      result += c;
  }
  return result;
}

} // namespace

TEST_CASE("index settings") {
  const char *argv[] = {
      "",
      "--index",
      "--index-file",
      "/index/file.txt",
      "--password-file",
      "/password/file.txt",
  };

  ns::settings settings(sizeof(argv) / sizeof(argv[0]),
                        const_cast<char *const *>(argv));

  settings(
      [](const std::filesystem::path &index_file,
         const std::filesystem::path &password_file) {
        CHECK(index_file.string() == "/index/file.txt");
        CHECK(password_file.string() == "/password/file.txt");
      },
      {}, {}, {}, {});
}

TEST_CASE("rainbow-index settings") {
  const char *argv[] = {
      "",
      "--rainbow-index",
      "--index-file",
      "/index/file.txt",
      "--password-length",
      "8",
      "--table-width",
      "128",
      "--table-length",
      "65536",
      "--seed",
      "42",
  };

  ns::settings settings(sizeof(argv) / sizeof(argv[0]),
                        const_cast<char *const *>(argv));

  settings({},
           [](const std::filesystem::path &index_file,
              std::string_view alphabet, std::uint8_t password_length,
              std::size_t width, std::size_t length,
              cracker::settings::seed_t seed) {
             CHECK(alphabet == make_alphabet(std::regex("[[:graph:]]")));
             CHECK(index_file.string() == "/index/file.txt");
             CHECK(password_length == 8);
             CHECK(width == 128);
             CHECK(length == 65536);
             CHECK(seed == 42);
           },
           {}, {}, {});
}

TEST_CASE("brute-force settings") {
  const auto expected_hash =
      cracker::md5::to_string(cracker::md5::calculator{}.end(nullptr, nullptr));

  const char *argv[] = {
      "",
      "--brute-force",
      "--hash",
      expected_hash.c_str(),
      "--alphabet-regex",
      "[[:alnum:]]",
      "--max-password-length",
      "8",
  };

  ns::settings settings(sizeof(argv) / sizeof(argv[0]),
                        const_cast<char *const *>(argv));

  settings({}, {},
           [&](cracker::md5::md5_t hash, std::string_view alphabet,
               std::uint8_t len) {
             CHECK(alphabet == make_alphabet(std::regex("[[:alnum:]]")));
             CHECK(expected_hash == cracker::md5::to_string(hash));
             CHECK(len == 8);
           },
           {}, {});
}

TEST_CASE("dictionary settings") {
  const auto expected_hash =
      cracker::md5::to_string(cracker::md5::calculator{}.end(nullptr, nullptr));

  const char *argv[] = {
      "",
      "--dictionary",
      "--hash",
      expected_hash.c_str(),
      "--index-file",
      "/index/file.txt",
      "--password-file",
      "/password/file.txt",
  };

  ns::settings settings(sizeof(argv) / sizeof(argv[0]),
                        const_cast<char *const *>(argv));

  settings({}, {}, {},
           [&](cracker::md5::md5_t hash,
               const std::filesystem::path &index_file,
               const std::filesystem::path &password_file) {
             CHECK(expected_hash == cracker::md5::to_string(hash));
             CHECK(index_file == "/index/file.txt");
             CHECK(password_file == "/password/file.txt");
           },
           {});
}

TEST_CASE("rainbow settings") {
  const auto expected_hash =
      cracker::md5::to_string(cracker::md5::calculator{}.end(nullptr, nullptr));

  const char *argv[] = {
      "",
      "--rainbow",
      "--hash",
      expected_hash.c_str(),
      "--index-file",
      "/index/file.txt",
      "--password-length",
      "8",
      "--table-width",
      "128",
      "--alphabet-regex",
      "[ABC]",
  };

  ns::settings settings(sizeof(argv) / sizeof(argv[0]),
                        const_cast<char *const *>(argv));

  settings({}, {}, {}, {},
           [&](cracker::md5::md5_t hash,
               const std::filesystem::path &index_file,
               const std::string_view alphabet, std::uint8_t password_len, std::size_t table_width) {
             CHECK(expected_hash == cracker::md5::to_string(hash));
             CHECK(index_file == "/index/file.txt");
             CHECK(alphabet == "ABC");
             CHECK(password_len == 8);
             CHECK(table_width == 128);
           });
}
