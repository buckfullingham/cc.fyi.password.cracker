#ifndef PASSWORD_CRACKER_BRUTE_FORCE_HPP
#define PASSWORD_CRACKER_BRUTE_FORCE_HPP

#include <algorithm>
#include <concepts>
#include <execution>
#include <iostream>
#include <istream>
#include <mutex>
#include <random>
#include <ranges>
#include <string>
#include <thread>
#include <vector>

namespace cracker {
namespace detail {

template <std::invocable<const std::string &> Visitor,
          std::uniform_random_bit_generator URBG>
void visit_all_passwords(std::atomic_bool &found, const std::string_view &chars,
                         const std::uint8_t max_length,
                         const std::string &prefix, const Visitor &visitor,
                         URBG &urbg) {
  if (visitor(prefix)) {
    found = true;
    return;
  }
  if (prefix.size() != max_length) {
    std::vector<char> next_chars(chars.begin(), chars.end());
    std::shuffle(next_chars.begin(), next_chars.end(), urbg);
    for (auto i = next_chars.begin(), e = next_chars.end(); i != e && !found;
         ++i) {
      visit_all_passwords(found, chars, max_length, prefix + *i, visitor, urbg);
    }
  }
}
} // namespace detail

template <std::invocable<const std::string &> Visitor>
void visit_all_passwords(
    const std::string_view &chars, const std::uint8_t max_length,
    Visitor visitor,
    std::atomic<std::mt19937::result_type> seed = std::random_device{}()) {

  visitor(static_cast<const std::string &>(""));

  // all the 1-length passwords
  const auto prefixes = [&]() {
    std::vector<std::string> result;
    std::vector<char> first_chars(chars.begin(), chars.end());
    std::mt19937 urbg(seed);
    std::shuffle(first_chars.begin(), first_chars.end(), urbg);
    for (auto c : first_chars)
      result.emplace_back(1u, c);
    return result;
  }();

  const auto chunk_size = std::max<std::size_t>(
      1, prefixes.size() / std::thread::hardware_concurrency());

  std::atomic_bool found = false;

  std::vector<std::thread> threads;

  for (const auto &chunk : prefixes | std::views::chunk(chunk_size)) {
    threads.emplace_back([=, &found, &seed]() {
      std::mt19937 urbg(seed.fetch_add(1));
      for (auto i = chunk.begin(), e = chunk.end(); i != e && !found; ++i) {
        detail::visit_all_passwords(found, chars, max_length, *i, visitor,
                                    urbg);
      }
    });
  }

  for (auto &thread : threads)
    thread.join();
}

/**
 * Visit all passwords (lines) from the provided stream with EOL character
 * delim.
 *
 * @tparam Visitor
 * @param stream
 * @param visitor
 * @param delim
 */
template <typename Visitor>
void visit_all_passwords(std::istream &stream, Visitor visitor,
                         char delim = '\n') {
  for (std::string line; !std::getline(stream, line, delim).fail();)
    visitor(static_cast<const std::string &>(line));
}

} // namespace cracker

#endif // PASSWORD_CRACKER_BRUTE_FORCE_HPP
