#ifndef CC_FYI_PASSWORD_CRACKER_MD5_HPP
#define CC_FYI_PASSWORD_CRACKER_MD5_HPP

#include <array>
#include <cstdint>
#include <string>

namespace cracker::md5 {

using md5_t = std::array<std::uint32_t, 4>;

/**
 * Calculate an MD5 hash as per the algorithm laid out in
 * https://en.wikipedia.org/wiki/MD5 and https://www.ietf.org/rfc/rfc1321.txt
 *
 * Call add(begin, end) to append chars to the stream being hashed.  Call
 * end(begin, end) to yield the md5_t containing the hash.
 *
 * calculator maintains the hash calculation's state between calls to add() and
 * end() and re-initialises its state upon leaving end().  It can therefore be
 * reused.
 */
class calculator {
public:
  ~calculator() = default;
  calculator(const calculator &) = delete;
  calculator &operator=(const calculator &) = delete;
  calculator &operator=(calculator &&) = delete;

  calculator();

  /**
   * Read 64 byte whole chunks of the range [begin, end), adding to the hash
   * state each time.
   * @param begin
   * @param end
   * @return end, if the [begin, end) range was a multiple of 64 bytes long;
   * otherwise the new begin of the range of unconsumed bytes.
   */
  const char *add(const char *begin, const char *end);

  /**
   * Complete the hash, reset the calculator's internal state & return the hash
   * value.
   * @param begin
   * @param end
   * @return the hash value.
   */
  md5_t end(const char *begin, const char *end);

private:
  void add_chunk(const char *chunk);
  std::uint64_t len_;
  md5_t state_;
};

[[nodiscard]] std::string to_string(const md5_t &);

/**
 * Read 32 ascii encoded hex chars into an md5_t.  Supports either all upper
 * case or all lower case characters.
 * @return the md5
 * @throws std::runtime_error if the string does not satisfy the correct format.
 */
[[nodiscard]] md5_t from_string(std::string_view);

} // namespace cracker::md5

#endif // CC_FYI_PASSWORD_CRACKER_MD5_HPP
