// SPDX-License-Identifier: GPL-3.0-or-later
//
// Error values returned by every fallible call of the library. No exception
// crosses the public API; failures are values.
#pragma once

#include <expected>
#include <string>
#include <utility>

namespace mcxanon {

// Values double as the CLI exit codes.
enum class ErrorCode : int {
  leak = 1,       // residual-leak scan found an original value; nothing published
  usage = 2,      // invalid arguments or request
  input = 3,      // unreadable, corrupt or unsupported input or project data
  collision = 4,  // an original equals a pseudonym already issued in the project
  busy = 5,       // the project is locked by another run
  internal = 70,  // defect in the tool
};

struct Error {
  ErrorCode code = ErrorCode::internal;
  std::string message;  // English; never contains an original value
};

template <class T>
using Result = std::expected<T, Error>;

[[nodiscard]] inline std::unexpected<Error> fail(ErrorCode code, std::string message) {
  return std::unexpected(Error{code, std::move(message)});
}

}  // namespace mcxanon
