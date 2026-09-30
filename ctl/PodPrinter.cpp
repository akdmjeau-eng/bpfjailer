// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/PodPrinter.h"

#include <cstring>
#include <string_view>

namespace bpfjailer::ctl {

namespace {

const char* enrollmentSourceName(unsigned char source) {
  switch (source) {
    case BPFJ_ENROLL_CLIENT:
      return "client";
    case BPFJ_ENROLL_EXE:
      return "exe";
    case BPFJ_ENROLL_EXE_SCAN:
      return "exe-scan";
    case BPFJ_ENROLL_CGROUP:
      return "cgroup";
    case BPFJ_ENROLL_CGROUP_SCAN:
      return "cgroup-scan";
    case BPFJ_ENROLL_XATTR:
      return "xattr";
    case BPFJ_ENROLL_DBUS:
      return "dbus";
    case BPFJ_ENROLL_FFC_TCP:
      return "ffc-tcp";
    case BPFJ_ENROLL_FFC_UDS:
      return "ffc-uds";
    case BPFJ_ENROLL_BASE_ROLE:
      return "base-role";
    case BPFJ_ENROLL_FFC_PTY:
      return "ffc-pty";
    default:
      return "unknown";
  }
}

// Nothing guarantees a pod's identity strings are terminated: the xattr
// enrollment path fills role_id straight from the xattr, which can fill the
// buffer exactly.
std::string_view boundedId(const char* id, std::size_t size) {
  return {id, ::strnlen(id, size)};
}

} // namespace

void printPod(std::ostream& os, const bpfj_pod& pod, std::int64_t nowNs) {
  os << "  pod " << uuidToString(pod.uuid) << "\n"
     << "    role:    " << boundedId(pod.role_id.id, ROLE_ID_LEN) << "\n"
     << "    user id: " << boundedId(pod.user_id.id, POD_USER_ID_LEN) << "\n"
     << "    source:  " << enrollmentSourceName(pod.enrollment_source) << "\n"
     << "    refs:    " << pod.refs << "\n"
     << "    age:     " << (nowNs - pod.creation_time_ns) / 1'000'000'000
     << "s\n";
}

} // namespace bpfjailer::ctl
