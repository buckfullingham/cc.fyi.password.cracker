#ifndef PASSWORD_CRACKER_SETTINGS_HPP
#define PASSWORD_CRACKER_SETTINGS_HPP

#include "md5.hpp"

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <random>
#include <regex>
#include <string>

namespace cracker {

class settings {
public:
  using seed_t = std::random_device::result_type;

  using index_cb_t = std::function<void(const std::filesystem::path &,
                                        const std::filesystem::path &)>;
  using rainbow_index_cb_t =
      std::function<void(const std::filesystem::path &, std::string_view,
                         std::uint8_t, std::size_t, std::size_t, seed_t)>;

  using brute_force_cb_t =
      std::function<void(md5::md5_t, std::string_view, std::uint8_t)>;

  using dictionary_cb_t =
      std::function<void(md5::md5_t, const std::filesystem::path &,
                         const std::filesystem::path &)>;

  using rainbow_cb_t = std::function<void(md5::md5_t, const std::filesystem::path &,
                         std::string_view, std::uint8_t, std::size_t)>;

  settings(int argc, char *const *argv);

  settings(const settings &) = delete;
  settings &operator=(const settings &) = delete;

  /*
   * use cases:
   *
   * index - build an index file from a password file
   * index_file password_file
   *
   * rainbow-index - build a rainbow table
   * index_file alphabet password_length width length seed
   *
   * brute - brute force a password from a hash
   * hash alphabet max_password_length
   *
   * dictionary - lookup a hash using an index and password files
   * hash password_file index_file
   *
   * rainbow - lookup a hash in a rainbow table
   * hash index_file password_length width
   *
   */
  void operator()(index_cb_t, rainbow_index_cb_t, brute_force_cb_t,
                  dictionary_cb_t, rainbow_cb_t) const;

private:
  std::optional<std::string> command_;
  std::optional<std::filesystem::path> index_file_;
  std::optional<std::filesystem::path> password_file_;
  std::optional<std::regex> alphabet_re_{"[[:graph:]]"};
  std::optional<std::uint8_t> password_length_{};
  std::optional<seed_t> seed_{std::random_device()()};
  std::optional<std::uint8_t> max_password_length_{};
  std::optional<md5::md5_t> hash_{};
  std::optional<std::size_t> table_width_{};
  std::optional<std::size_t> table_length_{};
};

} // namespace cracker

#endif // PASSWORD_CRACKER_SETTINGS_HPP
