// Copyright (c) Meta Platforms, Inc. and affiliates.

// Like hello.c, but reaching into libgreet.so, so that running it means the
// loader has had to map a second file the enforcer gets a say on.
//
// The call has to be real. A DT_NEEDED the program never calls would still be
// mapped by the loader, but a linker with --as-needed is free to drop it and
// the test would quietly stop covering anything.

int bpfjGreet(void);

int main(void) {
  return bpfjGreet();
}
