#ifndef PASSWORD_CRACKER_INDEX_HPP
#define PASSWORD_CRACKER_INDEX_HPP

#include "io.hpp"
#include "md5.hpp"

#include <functional>
#include <optional>
#include <tuple>

namespace cracker::index {

using record_t = std::tuple<md5::md5_t, std::uint64_t>;

struct less {
  using is_transparent = void;

  bool operator()(const record_t &lhs, const md5::md5_t &rhs) const {
    return std::get<0>(lhs) < rhs;
  }

  bool operator()(const md5::md5_t &lhs, const record_t &rhs) const {
    return lhs < std::get<0>(rhs);
  }
};

void build(const std::string &passwords_path, const std::string &index_path,
           char delim = '\n');

std::optional<std::string> lookup(const std::string &passwords_path,
                                  const std::string &index_path,
                                  cracker::md5::md5_t hash, char delim = '\n');

} // namespace cracker::index

#endif // PASSWORD_CRACKER_INDEX_HPP
