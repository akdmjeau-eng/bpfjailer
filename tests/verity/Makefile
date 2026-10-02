# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Fixtures for the fs-verity enforcer tests.
#
# Driven by tests/VerityEnforcerTest.cpp rather than by hand, which is why it
# is a makefile apart from the one at the tree root: signing a binary is a
# handful of openssl and setfattr invocations, and they read far better here
# than as fork/exec from inside a test body. The steps mirror the root
# Makefile's `signing-key` and `sign-binary`, because what the enforcer
# accepts is whatever those produce.
#
#   make -f tests/verity/Makefile OUT=<dir> fixture
#       the two programs, the shared object, private copies of the loader and
#       libc, and two key pairs -- one the policy will trust, one it will not.
#
#   make -f tests/verity/Makefile OUT=<dir> sign BIN=<file> DIGEST=<file> NAME=trusted
#       sign the raw digest in DIGEST with NAME's key and hang the signature
#       off BIN in the xattr the enforcer reads.
#
# ---------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------
#
# Beyond what the root Makefile already needs to build the tree:
#
#   glibc-static      `hello` is linked with -static. See below for why that
#                     is not optional.
#   openssl           the signing itself, as `make signed` uses it.
#   attr              setfattr, to put the signature where BPF reads it.
#   binutils          readelf, to prove the static link really came out with
#                     no shared object dependencies.
#   e2fsprogs         mkfs.ext4, for the filesystem the harness builds to put
#                     all of this on. fs-verity cannot be turned on under
#                     tmpfs, so the tests cannot simply use /tmp.
#
# On CentOS or Fedora:
#   `dnf install glibc-static openssl attr binutils e2fsprogs`
# On Debian or Ubuntu the first is part of libc6-dev and the rest keep their
# names.
#
# Nothing here has to be cleaned up. OUT is on the harness's scratch
# filesystem, which is an ext4 image on a loop device inside the test's own
# mount namespace, so the fixtures and the fs-verity state frozen onto them
# go away with the test. See scratchFsPath() in tests/Harness.h.
#
# ---------------------------------------------------------------------------
# Why the linking is the way it is
# ---------------------------------------------------------------------------
#
# The enforcer checks every executable mapping, not just the binary being
# exec'd, and that decides how each fixture has to be built.
#
# `hello` is static so that running it maps exactly one file. It is the
# fixture for the exec hook, and a verdict about one file is only clean if
# there is only one file to have a verdict about.
#
# `linked` is the opposite on purpose: it is dynamic, so running it maps
# libgreet.so as well and the mmap hook gets a say. That drags in the loader
# and libc, which are checked too -- so it is linked against *copies* of them
# staged in $(OUT). Enabling fs-verity on the system ld.so and libc.so.6
# would be both irreversible and machine-wide; copies can be frozen and
# thrown away with the rest of the fixture.
#
# Enabling fs-verity and reading back the digest are the test's own job: both
# are ioctls, the digest only exists once verity is on, and turning it on is
# irreversible -- which is why the root Makefile will not do it and why every
# test builds and signs fixtures of its own.

SEQ_XATTR ?= user.bpfj.seq

OUT ?=
CC ?= cc
OPENSSL ?= openssl
SETFATTR ?= setfattr

# The xattr the BPF side reads the signature from, spelled as
# BPFJ_EXEC_SIG_XATTR in bpfj/enforce/bpf/types.h. Same default as the root
# Makefile's SIGN_XATTR.
SIGN_XATTR ?= user.bpfj.sig

# Has to agree with what the kernel hashed the file with, since the digest is
# what gets signed. The test enables verity with SHA-256.
SIGN_HASH_ALG ?= sha256

# Resolved from this makefile's own location, so the caller's working
# directory does not have to be the tree root.
HERE := $(dir $(lastword $(MAKEFILE_LIST)))

ifeq ($(OUT),)
$(error set OUT to a writable directory on a filesystem that supports fs-verity)
endif

# RPATH rather than RUNPATH: RUNPATH is not searched for a dependency of a
# dependency, so libgreet.so's own libc would come from the system copy --
# which is unsigned, and which this must not touch.
DYNAMIC_LDFLAGS = \
	-Wl,--dynamic-linker=$(OUT)/ld.so \
	-Wl,-rpath,$(OUT) \
	-Wl,--disable-new-dtags

.PHONY: fixture sign

# The keys are only ever reached through the certificate's pattern rule, which
# make treats as intermediate and deletes on the way out -- taking with it the
# half of the pair that `sign` needs. Same reason the root Makefile marks its
# BPF objects secondary.
.SECONDARY: $(OUT)/trusted_key.pem $(OUT)/untrusted_key.pem

fixture: $(OUT)/hello $(OUT)/linked \
	$(OUT)/trusted_cert.der $(OUT)/untrusted_cert.der

$(OUT)/ld.so:
	@mkdir -p $(OUT)
	@loader=$$(readelf -l /bin/true 2>/dev/null | \
		sed -n 's/.*interpreter: \(.*\)\]/\1/p'); \
	if [ -z "$$loader" ]; then \
		echo "$@: could not work out the dynamic loader from /bin/true" >&2; \
		exit 1; \
	fi; \
	cp "$$loader" $@
	chmod u+w $@

$(OUT)/libc.so.6:
	@mkdir -p $(OUT)
	@libc=$$(ldd /bin/true 2>/dev/null | \
		sed -n 's/.*libc\.so\.6 => \([^ ]*\).*/\1/p'); \
	if [ -z "$$libc" ]; then \
		echo "$@: could not work out libc from /bin/true" >&2; \
		exit 1; \
	fi; \
	cp "$$libc" $@
	chmod u+w $@

# The readelf check is the point of building it static, so it is worth
# failing here rather than having the test report a denial it cannot explain.
$(OUT)/hello: $(HERE)hello.c
	@mkdir -p $(OUT)
	$(CC) -static -O2 -o $@ $<
	@needed=$$(readelf -d $@ 2>/dev/null | grep -c NEEDED || true); \
	if [ "$$needed" -ne 0 ]; then \
		echo "$@: has $$needed shared object dependencies, which the" >&2; \
		echo "    enforcer would check separately -- install glibc-static" >&2; \
		exit 1; \
	fi

$(OUT)/libgreet.so: $(HERE)greet.c | $(OUT)/ld.so $(OUT)/libc.so.6
	$(CC) -shared -fPIC -O2 -o $@ $< $(DYNAMIC_LDFLAGS)

$(OUT)/linked: $(HERE)linked.c $(OUT)/libgreet.so
	$(CC) -O2 -o $@ $< -L$(OUT) -lgreet $(DYNAMIC_LDFLAGS)

$(OUT)/%_key.pem:
	@mkdir -p $(OUT)
	$(OPENSSL) genrsa -out $@ 2048 2>/dev/null

# DER, because that is the form Keyring::addPKey() loads into a keyring, and
# so the form the policy file carries base64 of.
$(OUT)/%_cert.der: $(OUT)/%_key.pem
	$(OPENSSL) req -new -x509 -key $< -out $@ -outform der -days 365 \
		-subj "/CN=bpfj verity test $*"

# What is signed is the bare fs-verity digest -- 32 bytes for sha256 -- and
# not the fsverity_formatted_digest the kernel's own builtin signatures use.
# bpfj_check_fsverity_pkcs7() hands bpf_verify_pkcs7_signature() exactly those
# bytes, so signing anything else verifies against nothing.
sign:
	@if [ -z "$(BIN)" ] || [ -z "$(DIGEST)" ] || [ -z "$(NAME)" ]; then \
		echo "sign: needs BIN, DIGEST and NAME" >&2; \
		exit 1; \
	fi
# SEQ, when given, is appended to the digest so the signature covers the pair,
# and written to the xattr the enforcer reads it back from. Mirrors what the
# top-level makefile's sign-binary does for CMD_SEQ.
	$(if $(SEQ),printf '%016x' $(SEQ) | xxd -p -r >> $(DIGEST))
	$(OPENSSL) cms -sign -binary -in $(DIGEST) \
		-signer $(OUT)/$(NAME)_cert.der -inkey $(OUT)/$(NAME)_key.pem \
		-outform der -md $(SIGN_HASH_ALG) -nosmimecap -out $(DIGEST).p7s
	$(SETFATTR) -n $(SIGN_XATTR) -v "0s$$(base64 -w0 $(DIGEST).p7s)" $(BIN)
	$(if $(SEQ),$(SETFATTR) -n $(SEQ_XATTR) -v "0s$$(printf '%016x' $(SEQ) | xxd -p -r | base64 -w0)" $(BIN))
