// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdlib>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string_view>

// Minimal diagnostic logging, so the open source tree carries no logging
// dependency. Stream style, one line per message, to stderr:
//
//     BPFJ_LOG(ERR) << "heap: timed out taking the arena lock";
//
// The closed source tree routes the same call sites through folly's XLOG.

namespace bpfjailer::log {

enum class Level {
  INFO,
  WARN,
  ERR,
};

constexpr std::string_view levelName(Level level) noexcept {
  switch (level) {
    case Level::INFO:
      return "INFO";
    case Level::WARN:
      return "WARN";
    case Level::ERR:
      return "ERROR";
  }
  return "?";
}

/// @brief One log line, flushed when the temporary BPFJ_LOG builds it as dies
/// at the end of the full expression.
class Message {
 public:
  Message(
      Level level,
      std::string_view file,
      int line,
      bool fatal = false) noexcept
      : level_(level), file_(file), line_(line), fatal_(fatal) {}

  Message(const Message&) = delete;
  Message& operator=(const Message&) = delete;

  ~Message() noexcept {
    // A logger must not take down the process it is reporting on.
    try {
      std::clog << "[" << levelName(level_) << "] " << file_ << ":" << line_
                << "] " << buffer_.str() << '\n';
    } catch (...) {
    }
    if (fatal_) {
      ::std::abort();
    }
  }

  std::ostream& stream() noexcept {
    return buffer_;
  }

 private:
  Level level_;
  std::string_view file_;
  int line_;
  std::ostringstream buffer_;
  bool fatal_ = false;
};

// Collapses the streamed message to void so both arms of BPFJ_CHECK's
// conditional have the same type; lower precedence than <<.
struct Voidify {
  void operator&(std::ostream&) const noexcept {}
};

} // namespace bpfjailer::log

#define BPFJ_LOG(LEVEL)                                   \
  ::bpfjailer::log::Message(                              \
      ::bpfjailer::log::Level::LEVEL, __FILE__, __LINE__) \
      .stream()

// A condition that must hold, with a message. Stands in for XCHECK, logging
// and aborting because what it guards are programming errors the process
// cannot continue past -- a map published to BPF and then leaked, say.
//
//     BPFJ_CHECK(slot != nullptr) << "map not destroyed";
#define BPFJ_CHECK(COND)                                              \
  (COND) ? (void)0                                                    \
         : ::bpfjailer::log::Voidify() &                              \
          ::bpfjailer::log::Message(                                  \
              ::bpfjailer::log::Level::ERR, __FILE__, __LINE__, true) \
                  .stream()                                           \
              << "check failed: " #COND " "
