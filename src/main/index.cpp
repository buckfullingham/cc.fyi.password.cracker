#include "index.hpp"
#include "io.hpp"

#include <algorithm>
#include <execution>
#include <fstream>
#include <optional>
#include <span>

#include <fcntl.h>
#include <sys/stat.h>

void cracker::index::build(const std::string &passwords_path,
                           const std::string &index_path, const char delim) {
  {
    io::file_descriptor passwords_fd(::open, passwords_path.c_str(), O_RDWR);

    auto passwords_map = [&]() {
      struct stat st {};
      io::posix_call(::fstat, passwords_fd.value(), &st);
      return io::memory_map(nullptr, st.st_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, passwords_fd.value(), 0);
    }();

    auto [ptr, len] = passwords_map.value();

    auto begin = static_cast<const char *>(ptr);
    auto end = begin + len;

    std::ofstream index_stream(index_path);

    md5::calculator hasher;
    for (auto i = begin, j = std::find(i, end, delim); i < end;
         i = j + 1, j = std::find(i, end, delim)) {
      const record_t record(hasher.end(i, j), i - begin);
      index_stream.write(reinterpret_cast<const char *>(&record),
                         sizeof(record));
    };
  }

  {
    io::file_descriptor index_fd(::open, index_path.c_str(), O_RDWR);

    auto index_map = [&]() {
      struct stat st {};
      io::posix_call(::fstat, index_fd.value(), &st);
      return io::memory_map(nullptr, st.st_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, index_fd.value(), 0);
    }();

    auto [ptr, len] = index_map.value();

    std::sort(std::execution::par_unseq, static_cast<record_t *>(ptr),
              static_cast<record_t *>(ptr) + len / sizeof(record_t));
  }
}

std::optional<std::string>
cracker::index::lookup(const std::string &passwords_path,
                       const std::string &index_path, cracker::md5::md5_t hash,
                       const char delim) {
  std::optional<std::size_t> pos;

  io::file_descriptor index_fd(::open, index_path.c_str(), O_RDWR);

  auto index_map = [&]() {
    struct stat st {};
    io::posix_call(::fstat, index_fd.value(), &st);
    return io::memory_map(nullptr, st.st_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, index_fd.value(), 0);
  }();

  auto [ptr, len] = index_map.value();

  auto [begin, end] = std::equal_range(static_cast<const record_t *>(ptr),
                                       static_cast<const record_t *>(ptr) +
                                           len / sizeof(record_t),
                                       hash, less());

  if (begin == end)
    return {};

  io::file_descriptor passwords_fd(::open, passwords_path.c_str(), O_RDWR);

  auto passwords_map = [&]() {
    struct stat st {};
    io::posix_call(::fstat, passwords_fd.value(), &st);
    return io::memory_map(nullptr, st.st_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, passwords_fd.value(), 0);
  }();

  const char *const base =
      static_cast<char *>(std::get<0>(passwords_map.value()));

  return std::string(base + std::get<1>(*begin),
                     std::find(base + std::get<1>(*begin), base + len, delim));
}
