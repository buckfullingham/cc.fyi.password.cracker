#include <catch2/catch_all.hpp>

#include "rainbow.hpp"

#include <iostream>

namespace ns = cracker::rainbow;

TEST_CASE("create a single chain and find a password in it") {
  std::mt19937 prng(42);
  constexpr std::uint8_t password_len = 8;

  const auto md5 = [&](ns::password_t<password_len> p) {
    return cracker::md5::calculator{}.end(p.begin(), p.begin() + password_len);
  };

  const std::vector reduce_functions{
      ns::make_reduce_function<password_len>("01", 0),
      ns::make_reduce_function<password_len>("01", 1),
      ns::make_reduce_function<password_len>("01", 2),
      ns::make_reduce_function<password_len>("01", 3),
  };

  const auto [chain, passwords] = [&]() {
    std::tuple<ns::chain_t<password_len>,
               std::vector<ns::password_t<password_len>>>
        result{{{'0', '0', '0', '0', '0', '0', '0', '0'},
                {'0', '0', '0', '0', '0', '0', '0', '0'}},
               {{'0', '0', '0', '0', '0', '0', '0', '0'}}};

    for (auto &f : reduce_functions) {
      auto &pswd = std::get<0>(std::get<0>(result));
      pswd = f(md5(pswd));
      std::get<1>(result).push_back(pswd);
    }
    return result;
  }();

  std::cout << "passwords: ";
  for (auto &p : passwords)
    std::cout << std::string_view(p.begin(), p.end()) << ", ";
  std::cout << std::endl;

  const auto target = passwords[std::uniform_int_distribution<std::size_t>(
      0, passwords.size() - 1)(prng)];
  const auto target_md5 = md5(target);

  std::cout << "target     = " << std::string_view(target.begin(), target.end())
            << std::endl;
  std::cout << "target md5 = " << cracker::md5::to_string(target_md5)
            << std::endl;

  std::optional<ns::password_t<password_len>> found;

  for (std::size_t i = 1, e = reduce_functions.size(); i <= e; ++i) {
    ns::password_t<password_len> password;
    auto hash = target_md5;
    for (std::size_t j = e - i; j < e; ++j) {
      password = reduce_functions[j](hash);
      hash = md5(password);
    }

    if (password == std::get<0>(chain)) {
      password = std::get<1>(chain);
      for (std::size_t j = 0, f = e - i; j < f; ++j)
        password = reduce_functions[j](md5(password));
      if (md5(password) == target_md5)
        found = password;
    }
  }

  REQUIRE(found);
  CHECK(*found == target);
}

TEST_CASE("make_chain") {
  constexpr std::uint8_t password_len = 8;
  const std::string alphabet("01");
  const ns::password_t<password_len> init_password{'0', '0', '0', '0',
                                                   '0', '0', '0', '0'};
  const auto reducers = [&]() {
    std::vector<ns::reduce_function_t<password_len>> result;
    for (int i = 0; i < 32; ++i)
      result.push_back(ns::make_reduce_function<password_len>(alphabet, i));
    return result;
  }();

  const auto expected = [&]() {
    ns::chain_t<password_len> result{init_password, init_password};
    auto &pswd = std::get<0>(result);
    for (int i = 0; i < 32; ++i) {
      auto md5 = cracker::md5::calculator{}.end(pswd.begin(), pswd.end());
      pswd = ns::make_reduce_function<password_len>(alphabet, i)(md5);
    }
    return result;
  }();

  const auto actual = ns::make_chain<password_len>(
      init_password, reducers.begin(), reducers.end());

  CHECK(expected == actual);
  CHECK(std::get<0>(actual) != std::get<1>(actual));
}

TEST_CASE("gen_chains") {
  constexpr std::uint8_t password_len = 20;
  const std::string alphabet("01");
  std::vector<ns::chain_t<password_len>> v;

  std::vector<ns::reduce_function_t<password_len>> reduces;

  for (int i = 0; i < 1 << 9; ++i)
    reduces.push_back(ns::make_reduce_function<password_len>(alphabet, i));

  ns::gen_chains<password_len>(1 << 11, alphabet, 42, reduces.begin(),
                               reduces.end(), std::back_inserter(v));

  REQUIRE(!v.empty());
  CHECK(v[0] != v[1]);
  CHECK(v.size() == 1 << 11);
}

TEST_CASE("build table") {
  std::mt19937 urbg(42);
  constexpr std::uint8_t password_len = 10;
  std::array<ns::chain_t<password_len>, 1 << 5> table;

  ns::build_table<password_len>("01", 1 << 8, table.begin(), table.end(), urbg);

  CHECK(std::is_sorted(table.begin(), table.end()));
  CHECK(std::is_sorted(table.begin(), table.end(), ns::less<password_len>()));
  CHECK(std::unique(table.begin(), table.end()) == table.end());
}

TEST_CASE("compare two chains") {
  constexpr std::uint8_t password_len = 8;
  // clang-format off
  ns::chain_t<password_len> c1{{ '1', '0', '0', '0', '0', '0', '0', '0', },
                               { '0', '0', '0', '0', '0', '0', '0', '1', }};
  ns::chain_t<password_len> c2{{ '1', '0', '0', '0', '0', '0', '0', '1', },
                               { '0', '0', '0', '0', '0', '0', '0', '0', }};
  // clang-format on

  const ns::less<password_len> lt;
  const ns::equal<password_len> eq;

  CHECK(lt(c1, c2));
  CHECK(!lt(c1, c1));
  CHECK(!lt(c2, c2));
  CHECK(!lt(c2, c1));
  CHECK(eq(c1, c1));
  CHECK(eq(c2, c2));
  CHECK(!eq(c1, c2));
  CHECK(!eq(c2, c1));
}

TEST_CASE("compare chain and password") {
  constexpr std::uint8_t password_len = 10;
  // clang-format off
  ns::chain_t<password_len> c{
      { '1', '0', '0', '0', '0', '0', '0', '0', },
      { '0', '0', '0', '0', '0', '0', '0', '1', }
  };
  ns::password_t<password_len> p{
      '1', '0', '0', '0', '0', '0', '0', '1',
  };
  // clang-format on

  const ns::less<password_len> lt;

  CHECK(lt(c, p));
  CHECK(!lt(c, c));
  CHECK(!lt(p, c));
}

TEST_CASE("build and lookup") {
  std::vector<ns::chain_t<8>> table;
  table.resize(1024);
  std::mt19937 urbg(42);
  ns::build_table<8>("PASWORD", 1024, table.begin(), table.end(), urbg);

  const std::string expected = "PASSWORD";
  const auto hash = cracker::md5::calculator{}.end(
      &expected[0], &expected[0] + expected.size());
  const auto actual =
      ns::lookup<8>(hash, "PASWORD", 1024, table.begin(), table.end());

  REQUIRE(actual);
  CHECK(*actual == expected);
}
