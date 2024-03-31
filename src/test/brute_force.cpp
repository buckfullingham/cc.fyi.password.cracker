#include <catch2/catch_all.hpp>

#include "brute_force.hpp"

#include <iostream>
#include <iterator>
#include <mutex>
#include <random>
#include <set>

namespace ns = cracker;

TEST_CASE("generate all combinations of characters given a set of chars") {
  std::mutex mutex;
  std::vector<std::string> all_passwords;

  std::vector<std::string> expected_passwords{
      "", "a", "aa", "ab", "b", "ba", "bb",
  };

  ns::visit_all_passwords(
      "ab", 2,
      [&](const std::string &s) {
        std::scoped_lock guard(mutex);
        all_passwords.emplace_back(s);
        return false;
      },
      42);

  CHECK(all_passwords != expected_passwords); // shuffled
  std::sort(all_passwords.begin(), all_passwords.end());
  CHECK(all_passwords == expected_passwords); // unshuffled
}

TEST_CASE("read passwords from a stream") {
  std::stringstream ss;
  ss << "hello\nworld\n";
  std::vector<std::string> result;
  ns::visit_all_passwords(
      ss, [&](auto &password) { result.emplace_back(password); });
  CHECK(result == std::vector<std::string>{"hello", "world"});
}
