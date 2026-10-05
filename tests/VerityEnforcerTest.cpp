// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <fcntl.h>
#include <linux/fsverity.h>
#include <linux/keyctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#include <bpf/bpf.h>

#include "bpfj/enforce/Jailer.h"
#include "bpfj/enforce/Pins.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/Replace.h"
#include "bpfj/enforce/RoleId.h"
#include "bpfj/enforce/VerityEnforcer.h"
#include "bpfj/fsverity/Keyctl.h"
#include "bpfj/lib/Base64.h"
#include "bpfj/lib/bpf/types_scratch.h"

using bpfjailer::Jailer;
using bpfjailer::PinConfig;
using bpfjailer::Policy;
using bpfjailer::replaceJailer;
using bpfjailer::VerityEnforcer;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailerWithScratchMaps;
using bpfjailer::test::mapPinned;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

/// @brief The program started but did not exit 0, as a denied shared object
/// shows up after exec succeeds and the loader maps it.
constexpr int kRanAndFailed = -1;

/// @brief Bring up the jailer and the fs-verity enforcer over `toml`.
void attach(const std::string& toml) {
  const Policy policy = policyOf(toml);
  auto scratchMaps = loadJailerWithScratchMaps(policy);
  ASSERT_OK(VerityEnforcer::load(testPins(), policy, scratchMaps));
}

/// @brief Run `path` in a child and report 0, an exec errno or
/// `kRanAndFailed`; the grandchild keeps the caller alive to collect the
/// result after a successful exec.
[[nodiscard]] int runProgram(const std::string& path) {
  int report[2] = {-1, -1};
  if (::pipe(report) != 0) {
    return errno;
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    const int failed = errno;
    ::close(report[0]);
    ::close(report[1]);
    return failed;
  }

  if (pid == 0) {
    ::close(report[0]);

    const int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDOUT_FILENO);
      ::dup2(devnull, STDERR_FILENO);
    }

    std::string owned = path;
    char* const argv[] = {owned.data(), nullptr};
    ::execv(owned.c_str(), argv);

    const int failed = errno;
    (void)::write(report[1], &failed, sizeof(failed));
    ::_exit(127);
  }

  ::close(report[1]);

  int failed = 0;
  const ssize_t n = ::read(report[0], &failed, sizeof(failed));
  ::close(report[0]);

  int status = 0;
  (void)::waitpid(pid, &status, 0);

  if (n == static_cast<ssize_t>(sizeof(failed))) {
    return failed;
  }

  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : kRanAndFailed;
}

/// @brief Run `make` against the fixture makefile, ending the test if it fails.
void runMake(const std::vector<std::string>& args) {
  static constexpr char kMakefile[] = "tests/verity/Makefile";

  ASSERT(bpfjailer::test::exists(kMakefile));

  std::vector<std::string> owned{"make", "-f", kMakefile};
  owned.insert(owned.end(), args.begin(), args.end());

  std::vector<char*> argv;
  argv.reserve(owned.size() + 1);
  for (auto& arg : owned) {
    argv.push_back(arg.data());
  }
  argv.push_back(nullptr);

  const pid_t pid = ::fork();
  ASSERT(pid >= 0);

  if (pid == 0) {
    ::unsetenv("MAKEFLAGS");
    ::unsetenv("MFLAGS");

    const int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDOUT_FILENO);
    }

    ::execvp("make", argv.data());
    ::_exit(127);
  }

  int status = 0;
  ASSERT(::waitpid(pid, &status, 0) == pid);
  ASSERT(WIFEXITED(status));
  ASSERT_EQ(WEXITSTATUS(status), 0);
}

[[nodiscard]] std::string readFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

void writeFile(const std::string& path, const std::string& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  ASSERT(static_cast<bool>(out));
}

/// @brief The signable fixture: two programs, a shared object, the loader and
/// libc they run against, and two key pairs, rebuilt per test because
/// fs-verity cannot be undone.
class Fixture {
 public:
  Fixture() {
    std::string dir = bpfjailer::test::scratchFsPath() + "/fixture-XXXXXX";
    ASSERT(::mkdtemp(dir.data()) != nullptr);
    dir_ = dir;

    runMake({"OUT=" + dir_, "fixture"});
  }

  ~Fixture() = default;

  Fixture(const Fixture&) = delete;
  Fixture& operator=(const Fixture&) = delete;
  Fixture(Fixture&&) = delete;
  Fixture& operator=(Fixture&&) = delete;

  [[nodiscard]] std::string path(const std::string& name) const {
    return dir_ + "/" + name;
  }

  /// @brief Turn on fs-verity and return the digest the kernel reports.
  [[nodiscard]] std::string enableVerity(const std::string& file) {
    const int fd = ::open(file.c_str(), O_RDONLY);
    ASSERT(fd >= 0);

    struct fsverity_enable_arg enable{};
    enable.version = 1;
    enable.hash_algorithm = FS_VERITY_HASH_ALG_SHA256;
    enable.block_size = 4096;

    if (::ioctl(fd, FS_IOC_ENABLE_VERITY, &enable) != 0) {
      const int failed = errno;
      ::close(fd);
      ::bpfjailer::test::fail(
          __FILE__,
          __LINE__,
          "FS_IOC_ENABLE_VERITY",
          std::string("      ") + std::strerror(failed) +
              " -- the harness's scratch filesystem should have been made "
              "with fs-verity support");
    }

    // digest_size is in/out, sized for SHA-512 since older
    // <linux/fsverity.h> has no constant.
    constexpr std::size_t kMaxDigestSize = 64;
    std::vector<unsigned char> buf(
        sizeof(struct fsverity_digest) + kMaxDigestSize, 0);
    auto* digest = reinterpret_cast<struct fsverity_digest*>(buf.data());
    digest->digest_size = kMaxDigestSize;

    const int measured = ::ioctl(fd, FS_IOC_MEASURE_VERITY, digest);
    ::close(fd);
    ASSERT_EQ(measured, 0);

    return std::string(
        reinterpret_cast<const char*>(digest->digest), digest->digest_size);
  }

  /// @brief Sign `digest` with `name`'s key, into the xattr the enforcer reads.
  void sign(
      const std::string& file,
      const std::string& name,
      const std::string& digest) {
    // Named after the file so two of them in one fixture do not collide.
    const std::string digestPath = file + "." + name + ".digest";
    writeFile(digestPath, digest);

    runMake(
        {"OUT=" + dir_,
         "sign",
         "BIN=" + file,
         "DIGEST=" + digestPath,
         "NAME=" + name});
  }

  /// @brief Enable verity on `file` and sign it with the trusted key.
  void trust(const std::string& file) {
    sign(file, "trusted", enableVerity(file));
  }

  /// @brief Trust `file` at sequence `seq`.
  void trustAtSeq(const std::string& file, std::uint64_t seq) {
    const std::string digestPath = file + ".trusted.digest";
    writeFile(digestPath, enableVerity(file));

    runMake(
        {"OUT=" + dir_,
         "sign",
         "BIN=" + file,
         "DIGEST=" + digestPath,
         "NAME=trusted",
         "SEQ=" + std::to_string(seq)});
  }

  /// @brief Overwrite `file`'s sequence xattr, leaving the signature alone.
  void rewriteSeq(const std::string& file, std::uint64_t seq) {
    std::string be(8, '\0');
    for (int i = 0; i < 8; i++) {
      be[static_cast<std::size_t>(i)] = static_cast<char>(seq >> (8 * (7 - i)));
    }
    ASSERT(
        ::setxattr(file.c_str(), "user.bpfj.seq", be.data(), be.size(), 0) ==
        0);
  }

  /// @brief Trust the loader and libc `linked` runs against.
  void trustRuntime() {
    trust(path("ld.so"));
    trust(path("libc.so.6"));
  }

  /// @brief `name`'s base64-encoded certificate for a TOML string.
  [[nodiscard]] std::string certBlock(const std::string& name) const {
    const std::string der = readFile(path(name + "_cert.der"));
    ASSERT(!der.empty());

    const std::string b64 = bpfjailer::base64::encode(
        reinterpret_cast<const unsigned char*>(der.data()), der.size());

    return b64;
  }

 private:
  std::string dir_;
};

/// @brief A policy where `svc` will only run binaries signed by `trusted`.
[[nodiscard]] std::string signedPolicy(const Fixture& fixture) {
  return "[certs]\ntrusted = \"" + fixture.certBlock("trusted") +
      R"toml("

[roles.svc]
any = true
enforce-binary-certs = ["trusted"]
)toml";
}

/// @brief signedPolicy, plus a `min-seq` floor on `svc`.
[[nodiscard]] std::string sequencedPolicy(
    const Fixture& fixture,
    std::uint64_t minSeq) {
  return signedPolicy(fixture) + "min-seq = " + std::to_string(minSeq) + "\n";
}

/// @brief The serial of the keyring the enforcer built for `role`.
[[nodiscard]] bpfjailer::keyctl::Serial keyringOf(const std::string& role) {
  const auto id = bpfjailer::makeRoleId(role);
  ASSERT_OK(id);
  auto arena = bpfjailer::PodArena::open(testPins());
  ASSERT(arena);
  auto roles = bpfjailer::readRolePolicies(*arena);
  ASSERT_OK(roles);
  auto policy = bpfjailer::lookupRolePolicy(*roles, *id);
  ASSERT_OK(policy);
  ASSERT(*policy != nullptr);
  return static_cast<bpfjailer::keyctl::Serial>((*policy)->key_serial);
}

/// @brief Run `body` the way bpfjctl runs a load, in a process with its own
/// session keyring.
[[nodiscard]] bool inOwnSession(const std::function<bool()>& body) {
  const pid_t pid = ::fork();
  if (pid < 0) {
    return false;
  }

  if (pid == 0) {
    if (::syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, nullptr) < 0) {
      ::_exit(2);
    }
    ::_exit(body() ? 0 : 1);
  }

  int status = 0;
  if (::waitpid(pid, &status, 0) != pid) {
    bpfjailer::test::noteDiagnostic(
        "      session child could not be waited for\n");
    return false;
  }
  if (WIFSIGNALED(status)) {
    bpfjailer::test::noteDiagnostic(
        "      session child died from signal " +
        std::to_string(WTERMSIG(status)) + "\n");
    return false;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    bpfjailer::test::noteDiagnostic(
        WIFEXITED(status) && WEXITSTATUS(status) == 2
            ? "      session child could not create a session keyring\n"
            : "      session child body failed\n");
    return false;
  }
  return true;
}

/// @brief Whether the keyring `persist()` targets still links `serial`.
[[nodiscard]] bool persistKeyringHolds(bpfjailer::keyctl::Serial serial) {
  const long size =
      bpfjailer::keyctl::read(bpfjailer::keyctl::kSessionKeyring, nullptr, 0);
  if (size <= 0) {
    return false;
  }

  std::vector<char> buf(static_cast<std::size_t>(size));
  if (bpfjailer::keyctl::read(
          bpfjailer::keyctl::kSessionKeyring, buf.data(), buf.size()) != size) {
    return false;
  }

  const auto* linked =
      reinterpret_cast<const bpfjailer::keyctl::Serial*>(buf.data());
  for (std::size_t i = 0; i < buf.size() / sizeof(bpfjailer::keyctl::Serial);
       ++i) {
    if (linked[i] == serial) {
      return true;
    }
  }

  return false;
}

/// @brief Try to add a key to `keyring`; the errno, or 0 if it worked.
[[nodiscard]] int addKeyErrno(bpfjailer::keyctl::Serial keyring) {
  static constexpr char kPayload[] = "probe";

  errno = 0;
  const auto added = bpfjailer::keyctl::addKey(
      "user", "bpfj-probe", kPayload, sizeof(kPayload), keyring);
  return added < 0 ? errno : 0;
}

} // namespace

TEST(VerityEnforcer, LoadPinsBothLinksAndItsKeyMap) {
  attach(R"toml([roles]

[roles.svc]
)toml");

  ASSERT(linkPinned("bpfj_verity_mmap_file"));
  ASSERT(linkPinned("bpfj_verity_bprm_check"));
  ASSERT(!mapPinned("bpfj_role_policies"));
}

TEST(VerityEnforcer, LoadAgainstAPolicyNamingNoCertificateSucceeds) {
  attach(R"toml([roles]

[roles.svc]

[roles.worker]
)toml");

  ASSERT(linkPinned("bpfj_verity_bprm_check"));
}

TEST(VerityEnforcer, ARoleNamingNoCertificateGetsNoKeyMapEntry) {
  attach(R"toml([roles]

[roles.svc]

[roles.worker]
)toml");

  ASSERT_EQ(keyringOf("svc"), 0);
  ASSERT_EQ(keyringOf("worker"), 0);
}

TEST(VerityEnforcer, AJailedRoleNamingNoCertificateMayNotExec) {
  attach(R"toml([roles]

[roles.svc]
)toml");

  Child actor([] { return runProgram("/bin/true"); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, VerityAnyAllowsUnsignedExec) {
  attach(R"toml([roles]

[roles.svc]
verity-any = true
)toml");

  Child actor([] { return runProgram("/bin/true"); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(VerityEnforcer, OverrideStackedBoundsTheActorPolicyWalk) {
  attach(R"toml([roles]

[roles.denied]

[roles.override]
override-stacked = true
verity-any = true

[roles.top]
)toml");

  Child allowed([] { return runProgram("/bin/true"); });
  enroll("denied", allowed.pid());
  enroll("override", allowed.pid());
  ASSERT_EQ(allowed.run(), 0);

  Child denied([] { return runProgram("/bin/true"); });
  enroll("denied", denied.pid());
  enroll("override", denied.pid());
  enroll("top", denied.pid());
  ASSERT_EQ(denied.run(), EPERM);
}

TEST(VerityEnforcer, AnUnjailedProcessMayStillExec) {
  attach(R"toml([roles]

[roles.svc]
)toml");

  Child actor([] { return runProgram("/bin/true"); });

  ASSERT_EQ(actor.run(), 0);
}

TEST(VerityEnforcer, ARoleNamingACertificateGetsAKeyMapEntry) {
  Fixture fixture;
  attach(signedPolicy(fixture));

  ASSERT(keyringOf("svc") > 0);
}

TEST(VerityEnforcer, ASignedBinaryOnAVerityFileIsAllowed) {
  Fixture fixture;
  fixture.trust(fixture.path("hello"));

  attach(signedPolicy(fixture));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(VerityEnforcer, ABinarySignedByAnUntrustedKeyIsDenied) {
  Fixture fixture;

  const std::string hello = fixture.path("hello");
  fixture.sign(hello, "untrusted", fixture.enableVerity(hello));

  attach(signedPolicy(fixture));

  Child actor([hello] { return runProgram(hello); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, ASignatureOverTheWrongDigestIsDenied) {
  Fixture fixture;

  const std::string hello = fixture.path("hello");
  (void)fixture.enableVerity(hello);
  fixture.sign(hello, "trusted", std::string(32, '\0'));

  attach(signedPolicy(fixture));

  Child actor([hello] { return runProgram(hello); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, AnUnsignedBinaryIsDenied) {
  Fixture fixture;
  (void)fixture.enableVerity(fixture.path("hello"));

  attach(signedPolicy(fixture));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, ASignedBinaryWithoutFsVerityIsDenied) {
  Fixture fixture;

  fixture.sign(fixture.path("hello"), "trusted", std::string(32, '\0'));

  attach(signedPolicy(fixture));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, ASecondTreeDoesNotDisplaceTheFirstsKeyrings) {
  Fixture fixture;
  const Policy policy = policyOf(signedPolicy(fixture));

  attach(signedPolicy(fixture));
  const auto first = keyringOf("svc");
  ASSERT(persistKeyringHolds(first));

  // A second tree while the first is still attached, the shape a `replace`
  // builds; under one keyring name per role the second link would evict the
  // first out of the shared per-UID user keyring.
  PinConfig second = testPins();
  second.pinDir += "-second";
  auto scratchMaps = Jailer::load(second, policy);
  ASSERT(scratchMaps);
  ASSERT_OK(VerityEnforcer::load(second, policy, *scratchMaps));

  ASSERT(persistKeyringHolds(first));

  // Taking the second down works off the serials its own map holds.
  ASSERT_OK(Jailer::unload(second));
  ASSERT(persistKeyringHolds(first));
}

TEST(VerityEnforcer, UnloadReleasesTheKeyringsItBuilt) {
  Fixture fixture;
  attach(signedPolicy(fixture));

  const auto serial = keyringOf("svc");
  ASSERT(persistKeyringHolds(serial));

  ASSERT_OK(bpfjailer::Jailer::unload(testPins()));

  // Nothing but this link holds the keyring, bpfjctl's session keyring having
  // gone when it exited, so leaving it would strand the role's certificates.
  ASSERT(!persistKeyringHolds(serial));
}

TEST(VerityEnforcer, ASignedBinaryKeepsRunningAcrossAReplace) {
  Fixture fixture;
  fixture.trust(fixture.path("hello"));
  const Policy policy = policyOf(signedPolicy(fixture));

  ASSERT(inOwnSession([&] {
    auto scratchMaps = Jailer::load(testPins(), policy);
    return scratchMaps &&
        VerityEnforcer::load(testPins(), policy, *scratchMaps);
  }));

  const std::string hello = fixture.path("hello");
  int go[2] = {-1, -1};
  int stop[2] = {-1, -1};
  ASSERT_EQ(::pipe(go), 0);
  ASSERT_EQ(::pipe2(stop, O_NONBLOCK), 0);

  // A bare fork rather than a Child, whose run() releases and waits in one
  // call, since the replaces below happen while this is still exec'ing.
  const pid_t pid = ::fork();
  ASSERT(pid >= 0);
  if (pid == 0) {
    char c = 0;
    if (::read(go[0], &c, 1) != 1) {
      ::_exit(EIO);
    }
    while (::read(stop[0], &c, 1) != 1) {
      // Fork and exec enrollment are deliberately paused while replacement
      // snapshots task storage. Retry that transient safeguard, but preserve
      // every other execution failure.
      if (const int res = runProgram(hello); res != 0 && res != EBUSY) {
        ::_exit(res == kRanAndFailed ? 255 : res);
      }
    }
    ::_exit(0);
  }

  enroll("svc", pid);
  (void)::write(go[1], "x", 1);

  // Each replace unloads the old tree while this is running under it.
  int replaceReport[2] = {-1, -1};
  ASSERT_EQ(::pipe2(replaceReport, O_NONBLOCK), 0);
  const bool replaced = inOwnSession([&] {
    auto result = replaceJailer(testPins(), policy);
    if (!result) {
      const std::string diagnostic =
          "      replace: " + result.error().message() + "\n";
      (void)::write(replaceReport[1], diagnostic.data(), diagnostic.size());
    }
    return static_cast<bool>(result);
  });
  if (!replaced) {
    std::string diagnostic(1024, '\0');
    const ssize_t size =
        ::read(replaceReport[0], diagnostic.data(), diagnostic.size());
    if (size > 0) {
      diagnostic.resize(static_cast<std::size_t>(size));
      bpfjailer::test::noteDiagnostic(diagnostic);
    }
  }
  ::close(replaceReport[0]);
  ::close(replaceReport[1]);

  (void)::write(stop[1], "x", 1);
  int status = 0;
  ASSERT_EQ(::waitpid(pid, &status, 0), pid);
  for (const int fd : {go[0], go[1], stop[0], stop[1]}) {
    ::close(fd);
  }

  ASSERT(replaced);
  ASSERT(WIFEXITED(status));
  ASSERT_EQ(WEXITSTATUS(status), 0);
}

TEST(VerityEnforcer, DisarmKeepsTheKeyringsLinkedUntilRelease) {
  Fixture fixture;
  attach(signedPolicy(fixture));
  const auto serial = keyringOf("svc");

  const auto serials = VerityEnforcer::disarm(testPins());
  ASSERT_OK(serials);
  ASSERT(*serials == std::vector<bpfjailer::keyctl::Serial>{serial});
  ASSERT_EQ(keyringOf("svc"), 0);
  ASSERT(persistKeyringHolds(serial));

  VerityEnforcer::release(*serials);
  ASSERT(!persistKeyringHolds(serial));
}

TEST(VerityEnforcer, AKeyringSerialThatNoLongerResolvesIsDenied) {
  Fixture fixture;
  fixture.trust(fixture.path("hello"));

  attach(signedPolicy(fixture));

  // A properly signed binary and a role that trusts the signer, but a serial
  // that no longer names a keyring, as a displaced and reaped one leaves
  // behind; reading that as a valid signature would silently disarm the role.
  const auto id = bpfjailer::makeRoleId("svc");
  ASSERT_OK(id);

  auto arena = bpfjailer::PodArena::open(testPins());
  ASSERT(arena);
  auto roles = bpfjailer::readRolePolicies(*arena);
  ASSERT_OK(roles);
  auto policy = bpfjailer::lookupRolePolicy(*roles, *id);
  ASSERT_OK(policy);
  ASSERT(*policy != nullptr);
  const std::uint32_t unresolvable = 0x7ffffffe;
  const_cast<struct bpfj_role_policy*>(*policy)->key_serial = unresolvable;

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, AnUnjailedProcessMayRunAnUnsignedBinary) {
  // Positive control for the denials above: the role is what stops it.
  Fixture fixture;

  attach(signedPolicy(fixture));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });

  ASSERT_EQ(actor.run(), 0);
}

TEST(VerityEnforcer, AProgramWhoseSharedObjectIsSignedRuns) {
  Fixture fixture;
  fixture.trustRuntime();
  fixture.trust(fixture.path("libgreet.so"));
  fixture.trust(fixture.path("linked"));

  attach(signedPolicy(fixture));

  Child actor([path = fixture.path("linked")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(VerityEnforcer, AProgramWhoseSharedObjectIsUnsignedIsDenied) {
  Fixture fixture;
  fixture.trustRuntime();

  // The program passes the exec check and its unsigned library is caught by
  // the mmap_file hook, so this dies after starting rather than being refused.
  fixture.trust(fixture.path("linked"));
  (void)fixture.enableVerity(fixture.path("libgreet.so"));

  attach(signedPolicy(fixture));

  Child actor([path = fixture.path("linked")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), kRanAndFailed);
}

TEST(VerityEnforcer, AnUnsignedSharedObjectOnlyStopsAJailedProgram) {
  // Control for the test above, with only the enrollment taken away: without
  // it a library unloadable for its own reasons would read as a denial.
  Fixture fixture;
  fixture.trustRuntime();
  fixture.trust(fixture.path("linked"));
  (void)fixture.enableVerity(fixture.path("libgreet.so"));

  attach(signedPolicy(fixture));

  Child actor([path = fixture.path("linked")] { return runProgram(path); });

  ASSERT_EQ(actor.run(), 0);
}

// Who may write the keyrings the checks above verify against.

TEST(VerityEnforcer, LoadPinsTheKeyringGate) {
  attach(R"toml([roles]

[roles.svc]
)toml");

  ASSERT(linkPinned("bpfj_keyring_check"));
  ASSERT(mapPinned("bpfj_keyring_owner"));
  ASSERT(!mapPinned("bpfj_role_policies"));
  ASSERT(!mapPinned("bpfj_keyring_roles"));
  ASSERT(!mapPinned("bpfj_keyring_access"));
}

TEST(VerityEnforcer, AKeyringAnyRoleMayWriteAKeyring) {
  Fixture fixture;
  attach(signedPolicy(fixture) + "keyring-any = true\n");
  enroll("svc", ::getpid());

  ASSERT_EQ(addKeyErrno(keyringOf("svc")), 0);
}

TEST(VerityEnforcer, ARestrictedRoleMayNotWriteAnotherRolesKeyring) {
  Fixture fixture;
  attach(signedPolicy(fixture) + "[roles.other]\nkeyring-roles = []\n");
  enroll("other", ::getpid());

  // The bypass this exists to close: a certificate of `other`'s in the keyring
  // that decides what `svc` will run.
  ASSERT_EQ(addKeyErrno(keyringOf("svc")), EPERM);
}

TEST(VerityEnforcer, ARestrictedRoleMayWriteItsOwnKeyring) {
  Fixture fixture;
  attach(signedPolicy(fixture) + "keyring-own = true\n");
  enroll("svc", ::getpid());

  ASSERT_EQ(addKeyErrno(keyringOf("svc")), 0);
}

TEST(VerityEnforcer, ARoleWithNoKeyringMayNotWriteItsOwnKeyring) {
  Fixture fixture;
  attach(signedPolicy(fixture) + "keyring-own = false\n");
  enroll("svc", ::getpid());

  ASSERT_EQ(addKeyErrno(keyringOf("svc")), EPERM);
}

TEST(VerityEnforcer, ARoleNamedInAKeyringListMayWriteThatKeyring) {
  Fixture fixture;
  attach(signedPolicy(fixture) + "[roles.admin]\nkeyring-roles = [\"svc\"]\n");
  enroll("admin", ::getpid());

  ASSERT_EQ(addKeyErrno(keyringOf("svc")), 0);
}

TEST(VerityEnforcer, ARestrictedRoleMayNotWriteAKeyringItDidNotName) {
  Fixture fixture;
  attach(
      signedPolicy(fixture) +
      "[roles.other]\nenforce-binary-certs = [\"trusted\"]\n" +
      "[roles.admin]\nkeyring-roles = [\"other\"]\n");
  enroll("admin", ::getpid());

  // Named one keyring, which says nothing about the other.
  ASSERT_EQ(addKeyErrno(keyringOf("svc")), EPERM);
  ASSERT_EQ(addKeyErrno(keyringOf("other")), 0);
}

TEST(VerityEnforcer, EveryRoleWithAKeyringListHasToPermitTheWrite) {
  Fixture fixture;
  attach(
      signedPolicy(fixture) + "[roles.strict]\nkeyring-roles = []\n" +
      "[roles.admin]\nkeyring-roles = [\"svc\"]\n");
  enroll("strict", ::getpid());
  enroll("admin", ::getpid());

  ASSERT_EQ(addKeyErrno(keyringOf("svc")), EPERM);
}

TEST(VerityEnforcer, AnOverrideRoleAnswersForAKeyringWrite) {
  Fixture fixture;
  attach(
      signedPolicy(fixture) + "[roles.strict]\nkeyring-roles = []\n" +
      "[roles.admin]\noverride-stacked = true\n" +
      "keyring-roles = [\"svc\"]\n");
  enroll("strict", ::getpid());
  enroll("admin", ::getpid());

  ASSERT_EQ(addKeyErrno(keyringOf("svc")), 0);
}

TEST(VerityEnforcer, AProtectedKeyringIsStillSearchedForVerification) {
  Fixture fixture;
  fixture.trust(fixture.path("hello"));

  // The gate denies writes and nothing else: verification walks the keyring
  // with SEARCH, so a keyring nobody may write still runs a signed binary.
  attach(signedPolicy(fixture) + "[roles.other]\nkeyring-roles = []\n");

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

// Sequence numbers: rollback prevention for a signed binary. The floor lives in
// bpfj_verity_seq_map, is exactly what `min-seq` says, and nothing raises it as
// binaries run -- see RolePolicy::minSeq.

TEST(VerityEnforcer, ASequenceAtTheFloorRuns) {
  Fixture fixture;
  fixture.trustAtSeq(fixture.path("hello"), 5);

  attach(sequencedPolicy(fixture, 5));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  // Equal is not a rollback: it is the current binary running again.
  ASSERT_EQ(actor.run(), 0);
}

TEST(VerityEnforcer, ASequenceAboveTheFloorRuns) {
  Fixture fixture;
  fixture.trustAtSeq(fixture.path("hello"), 9);

  attach(sequencedPolicy(fixture, 5));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(VerityEnforcer, ASequenceBelowTheFloorIsDenied) {
  Fixture fixture;
  fixture.trustAtSeq(fixture.path("hello"), 3);

  attach(sequencedPolicy(fixture, 5));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, ARunDoesNotRaiseTheFloorAgainstAnOlderBinary) {
  Fixture fixture;
  fixture.trustRuntime();
  fixture.trust(fixture.path("libgreet.so"));
  fixture.trustAtSeq(fixture.path("hello"), 9);
  fixture.trustAtSeq(fixture.path("linked"), 6);

  // Both are above the floor, so running the newer one first does not retire
  // the older.
  attach(sequencedPolicy(fixture, 1));

  Child newer([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", newer.pid());
  ASSERT_EQ(newer.run(), 0);

  Child older([path = fixture.path("linked")] { return runProgram(path); });
  enroll("svc", older.pid());
  ASSERT_EQ(older.run(), 0);
}

TEST(VerityEnforcer, AReplaceRaisingMinSeqRetiresAnOlderBinary) {
  Fixture fixture;
  fixture.trustAtSeq(fixture.path("hello"), 3);

  attach(sequencedPolicy(fixture, 1));

  Child before([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", before.pid());
  ASSERT_EQ(before.run(), 0);

  // An edit and a replace is the one thing that moves the floor.
  ASSERT_OK(replaceJailer(testPins(), policyOf(sequencedPolicy(fixture, 5))));

  Child after([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", after.pid());

  ASSERT_EQ(after.run(), EPERM);
}

TEST(VerityEnforcer, AReplaceLoweringMinSeqAdmitsABinaryAgain) {
  Fixture fixture;
  fixture.trustAtSeq(fixture.path("hello"), 3);

  attach(sequencedPolicy(fixture, 5));

  Child before([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", before.pid());
  ASSERT_EQ(before.run(), EPERM);

  // The other direction, which an enforcer-raised floor could not offer.
  ASSERT_OK(replaceJailer(testPins(), policyOf(sequencedPolicy(fixture, 1))));

  Child after([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", after.pid());

  ASSERT_EQ(after.run(), 0);
}

TEST(VerityEnforcer, AReplaceDroppingMinSeqStopsSequenceChecking) {
  Fixture fixture;
  fixture.trustAtSeq(fixture.path("hello"), 9);

  attach(sequencedPolicy(fixture, 1));

  Child before([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", before.pid());
  ASSERT_EQ(before.run(), 0);

  // A role that stops naming `min-seq` wants a signature over the bare digest,
  // which this binary's is not.
  ASSERT_OK(replaceJailer(testPins(), policyOf(signedPolicy(fixture))));

  Child after([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", after.pid());

  ASSERT_EQ(after.run(), EPERM);
}

TEST(VerityEnforcer, ASignatureWithNoSequenceIsDeniedUnderAFloor) {
  Fixture fixture;

  // Signed the old way, over the bare digest, which is not a way out of a
  // role that demands a sequence number.
  fixture.trust(fixture.path("hello"));

  attach(sequencedPolicy(fixture, 1));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, ARewrittenSequenceIsDenied) {
  Fixture fixture;
  fixture.trustAtSeq(fixture.path("hello"), 3);

  // Why the sequence number is safe in an xattr fs-verity does not cover:
  // raising it by hand invalidates the signature over the old pair.
  fixture.rewriteSeq(fixture.path("hello"), 99);

  attach(sequencedPolicy(fixture, 5));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, ARoleWithNoFloorIgnoresASequence) {
  Fixture fixture;
  fixture.trustAtSeq(fixture.path("hello"), 3);

  // No min-seq, so the payload is the bare digest, and this binary's signature
  // is over the digest with a sequence appended.
  attach(signedPolicy(fixture));

  Child actor([path = fixture.path("hello")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EPERM);
}

TEST(VerityEnforcer, ASharedObjectNeedsNoSequenceUnderAFloor) {
  Fixture fixture;

  // The split `is_exec` draws: a sequence number belongs to the binary being
  // run, not to everything it maps. `linked` is both, so this also pins that
  // the mmap hook reads a sequence number where there is one.
  fixture.trustRuntime();
  fixture.trust(fixture.path("libgreet.so"));
  fixture.trustAtSeq(fixture.path("linked"), 7);

  attach(sequencedPolicy(fixture, 5));

  Child actor([path = fixture.path("linked")] { return runProgram(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

// The scratch pool the checks above take their buffers from.

TEST(VerityEnforcer, LoadDoesNotPinTheScratchPool) {
  attach(R"toml([roles]

[roles.svc]
)toml");

  ASSERT(!mapPinned("bpfj_scratch_small"));
  ASSERT(!mapPinned("bpfj_scratch_large"));
  ASSERT(!mapPinned("bpfj_scratch_small_claimed"));
  ASSERT(!mapPinned("bpfj_scratch_large_claimed"));
}

// Comfortably more executions than either pool has slots, so a guard that
// failed to give a slot back shows up as exhaustion.
constexpr int kMoreRunsThanSlots = BPFJ_SCRATCH_LARGE_SLOTS * 3 + 4;

TEST(VerityEnforcer, SlotsComeBackAcrossFarMoreRunsThanThePoolHolds) {
  Fixture fixture;
  fixture.trust(fixture.path("hello"));

  attach(signedPolicy(fixture));

  // Counting claimed slots instead would race every other exec on the host, so
  // provoke exhaustion, which makes bpfj_check_fsverity_pkcs7 start denying.
  Child actor([path = fixture.path("hello")] {
    for (int i = 0; i < kMoreRunsThanSlots; i++) {
      if (runProgram(path) != 0) {
        return 1;
      }
    }
    return 0;
  });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(VerityEnforcer, SlotsComeBackWhenEveryRunIsDenied) {
  Fixture fixture;
  fixture.trust(fixture.path("hello"));
  (void)fixture.enableVerity(fixture.path("linked"));

  attach(signedPolicy(fixture));

  // The denied path leaves the check through a different return than a pass.
  // Asserting the denials keep coming would prove nothing, since an empty pool
  // denies too, so what has to still work is a signed binary afterwards.
  Child actor(
      [signed_ = fixture.path("hello"), denied = fixture.path("linked")] {
        for (int i = 0; i < kMoreRunsThanSlots; i++) {
          if (runProgram(denied) == 0) {
            return 1;
          }
        }

        return runProgram(signed_) == 0 ? 0 : 2;
      });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}
