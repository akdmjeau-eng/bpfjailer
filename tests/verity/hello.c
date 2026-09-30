// Copyright (c) Meta Platforms, Inc. and affiliates.

// The binary the fs-verity enforcer tests exec when they want nothing more
// than a successful exec: `/bin/true` with a signature on it.
//
// Linked static by the makefile beside this file, so that running it maps
// exactly one file and a verdict about it is a verdict about this and
// nothing else. linked.c is the fixture for the other case.

int main(void) {
  return 0;
}
