#ifndef PASSWORD_CRACKER_RAINBOW_HPP
#define PASSWORD_CRACKER_RAINBOW_HPP

#include "io.hpp"
#include "md5.hpp"

#include <array>
#include <cstdint>
#include <execution>
#include <filesystem>
#include <functional>
#include <iterator>
#include <mutex>
#include <random>
#include <string_view>
#include <tuple>

#include <fcntl.h>
#include <sys/stat.h>

namespace cracker::rainbow {

using uint128_t = unsigned __int128;

using password_len_t = std::uint8_t;

template <password_len_t PasswordLength>
using password_t = std::array<char, PasswordLength>;

/**
 * Counter-intuitively, the chain endpoints are ordered the "wrong way round,"
 * i.e. last, first.  This is because searches are done on last so this makes
 * the chain ordering consistent with the table ordering.
 */
template <password_len_t PasswordLength>
using chain_t =
    std::tuple<password_t<PasswordLength>, password_t<PasswordLength>>;

template <std::uint8_t PasswordLength>
using reduce_function_t = std::function<password_t<PasswordLength>(md5::md5_t)>;

template <std::uint8_t PasswordLength>
reduce_function_t<PasswordLength>
make_reduce_function(const std::string_view alphabet, const int index) {
  const auto alphabet_size = alphabet.size();

  const auto space = [&]() {
    uint128_t result = 1;
    for (std::size_t i = 0; i < PasswordLength; ++i)
      result *= alphabet_size;
    return result;
  }();

  if (space <= index)
    throw std::invalid_argument("index is too large for the given alphabet");

  return [=](const md5::md5_t &md5) -> password_t<PasswordLength> {
    password_t<PasswordLength> result{};
    auto encode = [](const cracker::md5::md5_t &md5) {
      constexpr auto width = 8 * sizeof(cracker::md5::md5_t::value_type);
      uint128_t result = std::get<3>(md5);
      result <<= width;
      result |= std::get<2>(md5);
      result <<= width;
      result |= std::get<1>(md5);
      result <<= width;
      result |= std::get<0>(md5);
      return result;
    };

    uint128_t encoded_password = (encode(md5) + index) % space;
    for (std::uint8_t i = 0; i < PasswordLength; ++i) {
      result[i] = alphabet[encoded_password % alphabet_size];
      encoded_password /= alphabet_size;
    }
    return result;
  };
}

template <std::uint8_t PasswordLength, std::forward_iterator ForwardIterator>
chain_t<PasswordLength> make_chain(const password_t<PasswordLength> &init,
                                   ForwardIterator begin, ForwardIterator end) {
  chain_t<PasswordLength> result{init, init};

  std::for_each(begin, end, [&](const auto &reduce) {
    auto &pswd = std::get<0>(result);
    pswd = reduce(cracker::md5::calculator{}.end(pswd.begin(), pswd.end()));
  });

  return result;
}

template <std::uint8_t PasswordLength,
          std::output_iterator<chain_t<PasswordLength>> OutputIterator,
          std::forward_iterator ForwardIterator>
void gen_chains(std::size_t n, std::string_view alphabet,
                const std::uint64_t seed_, ForwardIterator begin,
                ForwardIterator end, OutputIterator o) {

  std::atomic_uint64_t seed = seed_;

  auto generator = [=, &seed]() {
    static thread_local auto urbg = [&]() {
      return std::mt19937_64(seed.fetch_add(1, std::memory_order_relaxed));
    }();

    std::uniform_int_distribution<std::size_t> next_index(0,
                                                          alphabet.size() - 1);

    auto chain = [&]() {
      const auto password = [&]() {
        password_t<PasswordLength> result;
        std::generate(result.begin(), result.end(),
                      [&]() { return alphabet[next_index(urbg)]; });
        return result;
      }();
      return chain_t<PasswordLength>(password, password);
    }();

    std::for_each(begin, end, [&](const auto &reduce) {
      auto &password = std::get<0>(chain);
      password = reduce(
          cracker::md5::calculator{}.end(password.begin(), password.end()));
    });

    return chain;
  };

  std::generate_n(std::execution::par_unseq, o, n, generator);
}

template <std::uint8_t PasswordLength> class less {
public:
  using is_transparent = void;

  bool operator()(const chain_t<PasswordLength> &lhs,
                  const chain_t<PasswordLength> &rhs) const {
    return lhs < rhs;
  }

  bool operator()(const chain_t<PasswordLength> &lhs,
                  const password_t<PasswordLength> &rhs) const {
    return std::get<0>(lhs) < rhs;
  }

  bool operator()(const password_t<PasswordLength> &lhs,
                  const chain_t<PasswordLength> &rhs) const {
    return lhs < std::get<0>(rhs);
  }
};

template <std::uint8_t PasswordLength> class equal {
public:
  using is_transparent = void;

  template <typename Lhs, typename Rhs>
    requires(std::is_same_v<Lhs, chain_t<PasswordLength>> ||
             std::is_same_v<Lhs, password_t<PasswordLength>>) &&
            (std::is_same_v<Rhs, chain_t<PasswordLength>> ||
             std::is_same_v<Rhs, password_t<PasswordLength>>)
  bool operator()(const Lhs &lhs, const Rhs &rhs) const {
    return !lt_(lhs, rhs) && !lt_(rhs, lhs);
  }

private:
  static constexpr less<PasswordLength> lt_{};
};

template <std::uint8_t PasswordLength, std::random_access_iterator Iterator,
          std::uniform_random_bit_generator URBG>
void build_table(const std::string_view alphabet, const std::size_t width,
                 const Iterator begin, const Iterator end, URBG &urbg) {

  const auto reducers = [&]() {
    std::vector<reduce_function_t<PasswordLength>> result;
    for (int i = 0; i < width; ++i)
      result.push_back(make_reduce_function<PasswordLength>(alphabet, i));
    return result;
  }();

  gen_chains<PasswordLength>(end - begin, alphabet, urbg(), reducers.begin(),
                             reducers.end(), begin);

  for (;;) {
    std::sort(std::execution::par_unseq, begin, end, less<PasswordLength>());
    auto pos = std::unique(begin, end);
    if (pos == end)
      break;
    gen_chains<PasswordLength>(end - pos, alphabet, urbg(), reducers.begin(),
                               reducers.end(), pos);
  }
}

template <std::uint8_t PasswordLength, std::uniform_random_bit_generator URBG>
void build_table(const std::filesystem::path &path, std::string_view alphabet,
                 const std::size_t width, const std::size_t length,
                 URBG &urbg) {
  const std::size_t file_size = sizeof(chain_t<PasswordLength>) * length;
  const io::file_descriptor fd(::open, path.c_str(),
                               O_RDWR | O_CREAT | O_TRUNC);
  io::posix_call(::ftruncate, fd.value(),
                 sizeof(chain_t<PasswordLength>) * length);
  io::memory_map mm(nullptr, file_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                    fd.value(), 0);
  const auto begin =
      static_cast<chain_t<PasswordLength> *>(std::get<0>(mm.value()));
  build_table<PasswordLength>(alphabet, width, begin, begin + length, urbg);
}

template <std::uint8_t PasswordLength, std::forward_iterator Iterator>
std::optional<std::string>
lookup(const md5::md5_t hash, const std::string_view alphabet,
       const std::size_t width, const Iterator begin, const Iterator end) {

  const auto reduce_functions = [&]() {
    std::vector<reduce_function_t<PasswordLength>> result;
    for (int i = 0; i < width; ++i)
      result.push_back(make_reduce_function<PasswordLength>(alphabet, i));
    return result;
  }();

  const auto compute_chain = [&reduce_functions, &hash](const std::size_t begin,
                                                        const std::size_t end) {
    password_t<PasswordLength> password;
    auto h = hash;
    for (std::size_t i = begin; i < end; ++i) {
      password = reduce_functions[i](h);
      h = md5::calculator{}.end(password.begin(), password.end());
    }
    return password;
  };

  const auto compute_password =
      [&reduce_functions](password_t<PasswordLength> password,
                          const std::size_t begin, const std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          password = reduce_functions[i](
              md5::calculator{}.end(password.begin(), password.end()));
        }
        return password;
      };

  for (std::size_t i = 1, e = reduce_functions.size(); i <= e; ++i) {
    const auto [eq_begin, eq_end] = std::equal_range(
        begin, end, compute_chain(e - i, e), less<PasswordLength>());

    for (auto j = eq_begin; j < eq_end; ++j) {
      const auto password = compute_password(std::get<1>(*j), 0, e - i);
      if (hash == md5::calculator{}.end(password.begin(), password.end()))
        return std::string(password.begin(), password.end());
    }
  }

  return {};
}

template <std::uint8_t PasswordLength>
std::optional<std::string>
lookup(const md5::md5_t hash, const std::filesystem::path &index_path,
       const std::string_view alphabet, const std::size_t width) {
  io::file_descriptor fd(::open, index_path.c_str(), O_RDONLY);
  struct ::stat st {};
  io::posix_call(::fstat, fd.value(), &st);
  io::memory_map mm(nullptr, st.st_size, MAP_SHARED, PROT_READ, fd.value(), 0);
  const auto [ptr, len] = mm.value();
  auto *begin = static_cast<chain_t<PasswordLength> *>(ptr);
  auto *end = begin + (st.st_size / sizeof(chain_t<PasswordLength>));
  return lookup<PasswordLength>(hash, alphabet, width, begin, end);
}
} // namespace cracker::rainbow

#endif // PASSWORD_CRACKER_RAINBOW_HPP
