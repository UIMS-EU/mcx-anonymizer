// SPDX-License-Identifier: GPL-3.0-or-later
//
// A bounded JSON reader and a canonical writer (RFC 8259; feature 007). The reader
// rejects anything outside the grammar, depths over 32, more than 4096 members and elements,
// strings over 64 KiB and invalid UTF-8; duplicate member names keep the first. The writer emits
// members in input order with minimal escapes and numbers as written.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mcxanon::http {

struct JsonMember;

struct Json {
  enum class Type { null, boolean, number, string, array, object };
  Type type = Type::null;
  bool boolean = false;
  std::string text;  // number: the literal; string: the decoded value (UTF-8)
  std::vector<Json> items;
  std::vector<JsonMember> members;

  static Json string_of(std::string s);
  static Json number_of(std::string s);
};

// A member of an object (first: the name, second: the value).
struct JsonMember {
  std::string first;
  Json second;
};

inline Json Json::string_of(std::string s) {
  Json j;
  j.type = Type::string;
  j.text = std::move(s);
  return j;
}
inline Json Json::number_of(std::string s) {
  Json j;
  j.type = Type::number;
  j.text = std::move(s);
  return j;
}

std::optional<Json> parse_json(std::string_view text);
std::string write_json(const Json& j);

}  // namespace mcxanon::http
