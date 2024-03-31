#include "settings.hpp"

#include "brute_force.hpp"
#include "index.hpp"
#include "md5.hpp"
#include "rainbow.hpp"

#include <cassert>
#include <charconv>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <optional>
#include <regex>
#include <string>
#include <utility>

#include <getopt.h>

namespace {
template <typename T>
  requires std::is_integral_v<std::remove_cvref_t<T>>
static std::optional<std::remove_cvref_t<T>> parse(std::string_view s) {
  std::remove_cvref_t<T> t;
  auto [ptr, ec] = std::from_chars(s.begin(), s.end(), t);
  if (*ptr || ec != std::errc())
    throw std::runtime_error("invalid integer");
  return t;
}

std::string make_alphabet(const std::regex &re) {
  std::string result;
  for (int i = 0; i < 128; ++i) {
    const char c = static_cast<char>(i);
    const char str[2]{c, '\0'};
    if (std::regex_match(str, re))
      result.push_back(c);
  }
  if (result.empty())
    throw std::runtime_error("alphabet-regex generates empty alphabet");
  return result;
}

} // namespace

cracker::settings::settings(int argc, char *const *argv) {
  const struct option long_options[] = {
      {"index", no_argument, nullptr, 'I'},
      {"rainbow-index", no_argument, nullptr, 'J'},
      {"brute-force", no_argument, nullptr, 'B'},
      {"dictionary", no_argument, nullptr, 'D'},
      {"rainbow", no_argument, nullptr, 'R'},
      {"alphabet-regex", required_argument, nullptr, 'r'},
      {"password-length", required_argument, nullptr, 'l'},
      {"max-password-length", required_argument, nullptr, 'm'},
      {"hash", required_argument, nullptr, 'h'},
      {"password-file", required_argument, nullptr, 'p'},
      {"index-file", required_argument, nullptr, 'i'},
      {"table-width", required_argument, nullptr, 'W'},
      {"table-length", required_argument, nullptr, 'L'},
      {"seed", required_argument, nullptr, 's'},
      {},
  };

  const auto short_options = [&]() {
    std::string result;
    for (auto &opt : long_options) {
      if (opt.val) {
        result.push_back(opt.val);
        switch (opt.has_arg) {
        case optional_argument:
          result.push_back(':');
        case required_argument:
          result.push_back(':');
        default:
          break;
        }
      }
    }
    return result;
  }();

  ::optind = 1;

  for (;;) {
    int option_index = 0;

    int c = ::getopt_long(argc, argv, short_options.c_str(), long_options,
                          &option_index);

    if (c == -1)
      break;

    switch (c) {
    case 'B':
    case 'I':
    case 'J':
    case 'D':
    case 'R': {
      auto pos = std::find_if(
          long_options,
          &long_options[sizeof(long_options) / sizeof(struct option) - 1],
          [&](auto &opt) { return c == opt.val; });
      assert(pos !=
             &long_options[sizeof(long_options) / sizeof(struct option)]);
      command_ = pos->name;
      break;
    }
    case 'h':
      hash_ = cracker::md5::from_string(optarg);
      break;
    case 'p':
      password_file_ = optarg;
      break;
    case 'i':
      index_file_ = optarg;
      break;
    case 'r':
      alphabet_re_ = std::regex(optarg);
      break;
    case 'l':
      password_length_ = parse<decltype(*password_length_)>(optarg);
      break;
    case 'm':
      max_password_length_ = parse<decltype(*max_password_length_)>(optarg);
      break;
    case 'W':
      table_width_ = parse<decltype(*table_width_)>(optarg);
      break;
    case 'L':
      table_length_ = parse<decltype(*table_length_)>(optarg);
      break;
    case 's':
      seed_ = parse<decltype(*seed_)>(optarg);
      break;
    }
  }
}

void cracker::settings::operator()(index_cb_t index_cb,
                                   rainbow_index_cb_t rainbow_index_cb,
                                   brute_force_cb_t brute_force_cb,
                                   dictionary_cb_t dictionary_cb,
                                   rainbow_cb_t rainbow_cb) const {

  auto throw_if_omitted = [](const auto &opt,
                             const std::string &s) -> const auto & {
    if (!opt)
      throw std::runtime_error(s + " not specified");
    else
      return *opt;
  };

  throw_if_omitted(command_, "command");

  if (*command_ == "brute-force") {
    auto &hash = throw_if_omitted(hash_, "hash");
    auto alphabet =
        make_alphabet(throw_if_omitted(alphabet_re_, "alphabet-regex"));
    auto &max_password_length =
        throw_if_omitted(max_password_length_, "max-password-length");
    brute_force_cb(hash, alphabet, max_password_length);
  } else if (*command_ == "index") {
    auto &index_file = throw_if_omitted(index_file_, "index-file");
    auto &password_file = throw_if_omitted(password_file_, "password-file");
    index_cb(index_file, password_file);
  } else if (*command_ == "rainbow-index") {
    auto &index_file = throw_if_omitted(index_file_, "index-file");
    auto alphabet =
        make_alphabet(throw_if_omitted(alphabet_re_, "alphabet-regex"));
    auto &password_length =
        throw_if_omitted(password_length_, "password-length");
    auto &table_width = throw_if_omitted(table_width_, "table-width");
    auto &table_length = throw_if_omitted(table_length_, "table-length");
    auto &seed = throw_if_omitted(seed_, "seed");
    rainbow_index_cb(index_file, alphabet, password_length, table_width,
                     table_length, seed);
  } else if (*command_ == "dictionary") {
    auto &hash = throw_if_omitted(hash_, "hash");
    auto &index_file = throw_if_omitted(index_file_, "index-file");
    auto &password_file = throw_if_omitted(password_file_, "password-file");
    dictionary_cb(hash, index_file, password_file);
  } else if (*command_ == "rainbow") {
    auto &hash = throw_if_omitted(hash_, "hash");
    auto &index_file = throw_if_omitted(index_file_, "index-file");
    auto &password_length =
        throw_if_omitted(password_length_, "password-length");
    auto &table_width = throw_if_omitted(table_width_, "table-width");
    auto alphabet =
        make_alphabet(throw_if_omitted(alphabet_re_, "alphabet-regex"));
    rainbow_cb(hash, index_file, alphabet, password_length, table_width);
  } else {
    throw std::runtime_error("bad command");
  }
}
