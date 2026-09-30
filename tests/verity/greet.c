// Copyright (c) Meta Platforms, Inc. and affiliates.

// The shared object `linked` pulls in. It exists to be a second file the
// enforcer has to be satisfied about, so what it computes does not matter --
// only that `linked` cannot run without having mapped it.

int bpfjGreet(void) {
  return 0;
}
