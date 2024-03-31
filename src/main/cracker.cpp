#include "settings.hpp"

#include "brute_force.hpp"
#include "index.hpp"
#include "md5.hpp"
#include "rainbow.hpp"

#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <utility>

namespace {

template <std::uint8_t len>
using len_t = std::integral_constant<std::uint8_t, len>;

template <typename F> inline void with_password_length(std::uint8_t i, F &&f) {
  switch (i) {
  case 4:
    return f(len_t<4>());
  case 5:
    return f(len_t<5>());
  case 6:
    return f(len_t<6>());
  case 7:
    return f(len_t<7>());
  case 8:
    return f(len_t<8>());
  case 9:
    return f(len_t<9>());
  case 10:
    return f(len_t<10>());
  case 11:
    return f(len_t<11>());
  case 12:
    return f(len_t<12>());
  case 13:
    return f(len_t<13>());
  case 14:
    return f(len_t<14>());
  case 15:
    return f(len_t<15>());
  default:
    throw std::runtime_error("unsupported password length");
  }
}

} // namespace

int main(int argc, char *argv[]) {
  cracker::settings settings(argc, argv);

  settings(
      [](const std::filesystem::path &index_path,
         const std::filesystem::path &passwords_path) {
        cracker::index::build(passwords_path, index_path, '\n');
      },
      [](const std::filesystem::path &index_path, std::string_view alphabet,
         const std::uint8_t password_length, std::size_t width,
         std::size_t length, auto seed) {
        std::mt19937_64 urbg(seed);
        with_password_length(password_length, [&](const auto len) {
          cracker::rainbow::build_table<len>(index_path, alphabet, width,
                                             length, urbg);
        });
      },
      [](const cracker::md5::md5_t hash, const std::string_view alphabet,
         const std::uint8_t max_password_len) {
        std::mutex mutex;
        cracker::visit_all_passwords(
            alphabet, max_password_len, [=, &mutex](const auto &password) {
              if (hash == cracker::md5::calculator{}.end(
                              &password[0], &password[0] + password.size())) {
                std::scoped_lock lock(mutex);
                std::cout << password << std::endl;
                return true;
              }
              return false;
            });
      },
      [](cracker::md5::md5_t hash, const std::filesystem::path &index_path,
         const std::filesystem::path &passwords_path) {
        const auto password =
            cracker::index::lookup(passwords_path, index_path, hash);
        if (password)
          std::cout << *password << std::endl;
      },
      [](cracker::md5::md5_t hash, const std::filesystem::path &index_path,
         const std::string_view alphabet, const std::uint8_t password_length,
         const std::size_t width) {
        with_password_length(password_length, [&](const auto len) {
          const auto password =
              cracker::rainbow::lookup<len>(hash, index_path, alphabet, width);
          if (password)
            std::cout << *password << std::endl;
        });
      });

  return EXIT_SUCCESS;
}
