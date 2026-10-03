// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/types.h>

#include <functional>
#include <span>
#include <string>
#include <string_view>

#include "bpfj/enforce/Pins.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/ScratchMapFds.h"
#include "bpfj/policy/Policy.h"

// What the enforcer tests share: every enforcer comes up the same way -- a
// policy, a jailer, then the enforcer over the jail membership maps it created
// -- and every behavioural test needs a second process to act on.

namespace bpfjailer::test {

/// @brief A pin config over the bpffs this test has to itself.
[[nodiscard]] PinConfig testPins();

/// @brief Parse `yaml`, ending the test if it does not parse.
[[nodiscard]] Policy policyOf(const std::string& yaml);

/// @brief Bring the jailer up under testPins(), ending the test if it fails;
/// every enforcer expects this to have created the maps it adopts.
void loadJailer(const Policy& policy);

/// @brief Bring the jailer up and retain its scratch map FDs for another BPF
/// object to reuse.
[[nodiscard]] ScratchMapFds loadJailerWithScratchMaps(const Policy& policy);

/// @brief Whether an enforcer link named `name` is pinned under testPins().
[[nodiscard]] bool linkPinned(std::string_view name);

/// @brief Whether a map named `name` is pinned under testPins().
[[nodiscard]] bool mapPinned(std::string_view name);

/// @brief Whether the pinned map `name` holds no entries at all.
[[nodiscard]] bool pinnedMapIsEmpty(std::string_view name);

/// @brief Put `pid` in a new pod of `role`, ending the test if it fails.
/// Always Threads::All, every caller enrolling an already-running process, and
/// each call makes a *new* pod -- only fork shares one, which is what the
/// own-pod tests turn on.
void enroll(std::string_view role, pid_t pid);

/// @brief The variable-carrying form of enroll().
void enroll(std::string_view role, pid_t pid, std::span<const PodVar> vars);

/// @brief A forked child the test drives, two ways: as a target left waiting
/// for something else to signal, attach to or open, or as an actor released by
/// run() once its enrollment is in place. When it forks is load bearing -- a
/// Child built after its parent was enrolled inherits the parent's pod -- and
/// it stays alive after reporting, so a BPF object its body created is still
/// there for the next child to open.
class Child {
 public:
  /// @brief Fork a child that waits for run(). By convention `body` returns
  /// 0 for success and an errno otherwise, which is how these tests read a
  /// denial.
  explicit Child(std::function<int()> body = [] { return 0; });
  ~Child();

  Child(const Child&) = delete;
  Child& operator=(const Child&) = delete;
  Child(Child&&) = delete;
  Child& operator=(Child&&) = delete;

  [[nodiscard]] pid_t pid() const noexcept {
    return pid_;
  }

  /// @brief Release the child and return what its body returned.
  [[nodiscard]] int run();

 private:
  std::function<int()> body_;
  pid_t pid_ = -1;
  int goFd_ = -1;
  int resultFd_ = -1;
};

} // namespace bpfjailer::test
