#include "md5.hpp"

#include <bit>

namespace {
constexpr std::array<int, 64> s = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

constexpr std::array<std::uint32_t, 64> K = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu,
    0x4787c62au, 0xa8304613u, 0xfd469501u, 0x698098d8u, 0x8b44f7afu,
    0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu,
    0x49b40821u, 0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u, 0x21e1cde6u,
    0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u,
    0x676f02d9u, 0x8d2a4c8au, 0xfffa3942u, 0x8771f681u, 0x6d9d6122u,
    0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u,
    0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u, 0xf4292244u, 0x432aff97u,
    0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du,
    0x85845dd1u, 0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
};

constexpr cracker::md5::md5_t init_state{0x67452301, 0xefcdab89, 0x98badcfe,
                                         0x10325476};

char *unpack(std::uint64_t i, char *o) {
  auto shift = [](std::uint64_t i, int shift) -> char {
    return static_cast<char>(i >> shift);
  };
  *o++ = shift(i, 0);
  *o++ = shift(i, 8);
  *o++ = shift(i, 16);
  *o++ = shift(i, 24);
  *o++ = shift(i, 32);
  *o++ = shift(i, 40);
  *o++ = shift(i, 48);
  *o++ = shift(i, 56);
  return o;
}

std::array<std::uint32_t, 16> pack_chunk(const char *const chars) {
  std::array<std::uint32_t, 16> result{};

  auto pack_int = [](const char *const chars) -> std::uint32_t {
    auto shift = [](const char c, const int s) -> std::uint32_t {
      return static_cast<std::uint32_t>(static_cast<unsigned char>(c)) << s;
    };
    return shift(chars[0], 0) | shift(chars[1], 8) | shift(chars[2], 16) |
           shift(chars[3], 24);
  };

  for (int i = 0; i < result.size(); ++i)
    result[i] = pack_int(chars + i * 4);

  return result;
}
} // namespace

cracker::md5::calculator::calculator() : len_(), state_(init_state) {}

void cracker::md5::calculator::add_chunk(const char *const chunk) {
  auto M = pack_chunk(chunk);
  auto [A, B, C, D] = state_;
  for (int i = 0; i < 64; ++i) {
    std::uint32_t F;
    std::uint32_t g;
    if (i < 16) {
      F = (B & C) | ((~B) & D);
      g = i;
    } else if (i < 32) {
      F = (D & B) | ((~D) & C);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      F = B ^ C ^ D;
      g = (3 * i + 5) % 16;
    } else {
      F = C ^ (B | (~D));
      g = (7 * i) % 16;
    }
    F = F + A + K[i] + M[g];
    A = D;
    D = C;
    C = B;
    B = B + std::rotl(F, s[i]);
  }
  std::get<0>(state_) += A;
  std::get<1>(state_) += B;
  std::get<2>(state_) += C;
  std::get<3>(state_) += D;
}

const char *cracker::md5::calculator::add(const char *begin,
                                          const char *const end) {
  for (;;) {
    if (end - begin < 64)
      return begin;
    add_chunk(begin);
    len_ += 512;
    begin += 64;
  }
}

cracker::md5::md5_t cracker::md5::calculator::end(const char *begin,
                                                  const char *end) {
  std::array<char, 64> pad{};
  char *o = pad.begin();

  begin = add(begin, end);
  len_ += 8 * (end - begin);
  o = std::copy(begin, end, o);
  *o++ = static_cast<char>(0x80);

  if (56 < o - pad.begin()) {
    std::fill(o, pad.end(), 0);
    add_chunk(pad.begin());
    o = pad.begin();
  }

  std::fill(o, pad.begin() + 56, 0u);
  unpack(len_, pad.begin() + 56);
  add_chunk(pad.begin());

  len_ = 0;
  return std::exchange(state_, init_state);
}

[[nodiscard]] std::string cracker::md5::to_string(const md5_t &md5) {
  std::string result;
  result.reserve(33);

  auto add_byte = [&](std::uint8_t i) {
    constexpr char hex[] = "0123456789abcdef";
    result += hex[i / 16];
    result += hex[i % 16];
  };

  auto add_int = [&](std::uint32_t i) {
    add_byte(i);
    add_byte(i >> 8);
    add_byte(i >> 16);
    add_byte(i >> 24);
  };

  add_int(std::get<0>(md5));
  add_int(std::get<1>(md5));
  add_int(std::get<2>(md5));
  add_int(std::get<3>(md5));
  return result;
}
