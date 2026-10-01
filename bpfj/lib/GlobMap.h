// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bpfj/err/StdExpected.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/lib/bpf/types_glob_map.h"

namespace bpfjailer {

// Turns the NAME in a ${NAME} reference into the key the BPF side binds it by:
// never 0, and the same key the caller's converter puts in the lookup's
// bpfj_glob_bindings. What a key means is the caller's business -- a
// VarManager id, say -- which is what keeps this compiler free of any one var
// type.
using GlobKeyResolver =
    std::function<err::Expected<__u32>(std::string_view name)>;

// Userspace builder for a bpfj_glob_map. Compiles all glob patterns (literals,
// '?', '*' and ${NAME} variable references) into the single bit-parallel NFA
// consumed by the BPF matcher in glob_map.h. See types_glob_map.h for the
// compiled layout. Variable names are resolved to keys by the caller's
// GlobKeyResolver, and the caller binds values per lookup under the same keys.
//
// The compiled header lives on the arena: init() allocates it and publishes the
// arena pointer through `slot` -- the caller's chosen location for it, a .bss
// global or a bpfj_file_matcher field, which is how BPF finds the map. The
// arena is mapped at the same address in both worlds, so the pointer is valid
// on either side. destroy() frees the header and nulls the slot again.
//
// destroy() pairs with a *successful* init() only: an init() that fails unwinds
// its own allocations and leaves the slot null, so a caller that gives up on a
// failed init() owes nothing and the destructor's check still holds.
//
// NOT CONCURRENT WITH LOOKUPS. Both init() and destroy() mutate the published
// slot and the blocks it points at in place, with no handshake against a BPF
// matcher that may be reading them, so the caller must have no lookup in
// flight across either call. destroy() is the sharp end: it frees the mask,
// state, accept and gadget tables first and nulls the slot only at the very
// end, so a concurrent bpfj_glob_map_lookup would walk a still-published header
// into arena blocks the heap has already taken back -- and feed whatever it
// read there into an allow/deny decision. init() is milder but still visible: a
// lookup racing it sees a null slot or a published-but-empty header and reports
// zero matches.
//
// What holds today is the wiring, not the code: init() is only reached through
// FileMatchCached's setupMaps(), which runs inside a pre-attach callback, so no
// program is attached and no lookup can be in flight. A caller that wants to
// recompile a live map needs build-into-a-new-block-and-swap here instead.
template <heap::BpfSkelWithHeap Skel>
class GlobMap {
 public:
  GlobMap(
      std::shared_ptr<Skel> skel,
      struct bpfj_glob_map*& slot,
      bool checkDestroy = true)
      : skel_{std::move(skel)}, slot_(&slot), checkDestroy_(checkDestroy) {}

  ~GlobMap() {
    // slot_ is null for a moved-from instance; nothing to check or free.
    if (slot_ == nullptr) {
      return;
    }
    BPFJ_CHECK(!checkDestroy_ || *slot_ == nullptr) << "GlobMap not destroyed";
  }

  void swap(GlobMap& other) noexcept {
    std::swap(skel_, other.skel_);
    std::swap(slot_, other.slot_);
    std::swap(checkDestroy_, other.checkDestroy_);
    std::swap(resolveKey_, other.resolveKey_);
  }

  GlobMap(GlobMap&& other) noexcept {
    swap(other);
  }

  GlobMap& operator=(GlobMap&& other) noexcept {
    swap(other);
    return *this;
  }

  GlobMap(const GlobMap&) = delete;
  GlobMap& operator=(const GlobMap&) = delete;

  // resolveKey: turns each ${NAME} into its binding key; empty when the
  // patterns carry no variables, which makes a ${NAME} a compile error. map:
  // glob pattern (string) -> value.
  template <typename T>
  err::Expected<> init(GlobKeyResolver resolveKey, T&& map) {
    // destroy() and the destructor both check this; init() is the one public
    // entry point that wrote through the slot without looking, so on a
    // moved-from instance it dereferenced null rather than returning an error.
    if (slot_ == nullptr) {
      return err::Error(
          std::errc::invalid_argument,
          "Cannot init a moved-from GlobMap: it has no slot to publish into");
    }

    // Release a prior init()'s header and tables, so re-compiling into the same
    // GlobMap does not leak the previous arena blocks. No-op on the first call.
    destroy();
    *slot_ = heap::alloc<struct bpfj_glob_map>(skel_);
    if (hdr() == nullptr) {
      return err::Error(
          std::errc::not_enough_memory, "Failed to allocate glob map header");
    }

    // Every failure below this point has the header allocated and published in
    // *slot_. Hand it back rather than leave it for the caller: a failed init()
    // is not something callers destroy(), and the destructor's BPFJ_CHECK would
    // abort on the still-published slot. Dismissed once store() succeeds.
    // destroy() reads the header to decide what else to free, which is safe at
    // any point here -- heap::alloc value-initializes it, and nothing writes
    // the table pointers until store() completes.
    auto headerGuard = makeGuard([this] { destroy(); });

    resolveKey_ = std::move(resolveKey);
    // Pass 1: compile each pattern and pack it into a word (assign word+base).
    // numWords is only final after this pass, and the table stride depends on
    // it, so the tables are filled in pass 2.
    std::vector<Compiled> compiled;
    std::vector<CompiledPattern> patterns;
    compiled.reserve(map.size());
    patterns.reserve(map.size());

    __u32 numWords = 0;
    __u32 wordUsed = 0; // bits used in the current (last) word
    for (auto&& [pattern, v] : map) {
      Compiled c;
      if (auto res = compile(pattern, c); !res) {
        return res.error();
      }

      // (width + 1 accept bit) must fit in one 64-bit word.
      const __u32 need = c.numBits + 1;
      if (numWords == 0 || wordUsed + need > 64) {
        if (numWords >= BPFJ_GLOB_MAP_MAX_WORDS) {
          return err::Error(
              std::errc::argument_list_too_long, "Too many glob patterns");
        }
        ++numWords;
        wordUsed = 0;
      }

      const __u32 word = numWords - 1;
      const __u32 base = wordUsed;
      wordUsed += need;

      std::uint64_t val = 0;
      static_assert(sizeof(val) >= sizeof(v));
      std::memcpy(&val, &v, sizeof(v));
      patterns.push_back(CompiledPattern{word, base + c.numBits, val});
      compiled.push_back(std::move(c));
    }

    // The BPF matcher's accept-collection loop is bounded by
    // BPFJ_GLOB_MAP_MAX_ACCEPTS, so any pattern past that bound would be
    // silently never evaluated (a fail-open false-negative). Reject up front.
    // (The per-word guard above bounds words, not total patterns: each word can
    // pack up to 63 patterns, so words * patterns/word can exceed this cap.)
    if (patterns.size() > BPFJ_GLOB_MAP_MAX_ACCEPTS) {
      return err::Error(
          std::errc::argument_list_too_long, "Too many glob patterns");
    }

    // Pass 2: build the tables now that numWords (the stride) is known, and
    // collect the gadgets at their absolute (word, base) positions.
    std::vector<__u64> charMask(static_cast<std::size_t>(numWords) * 256, 0);
    std::vector<__u64> starMask(numWords, 0);
    std::vector<__u64> initState(numWords, 0);
    std::vector<__u32> gadgetWord;
    std::vector<__u32> gadgetBase;
    std::vector<__u32> gadgetKey;
    for (std::size_t i = 0; i < compiled.size(); ++i) {
      const __u32 word = patterns[i].word;
      const __u32 base = patterns[i].acceptBit - compiled[i].numBits;
      placePattern(
          charMask, starMask, initState, numWords, word, base, compiled[i]);
      for (auto&& [relBase, key] : compiled[i].gadgets) {
        gadgetWord.push_back(word);
        gadgetBase.push_back(base + relBase);
        gadgetKey.push_back(key);
      }
    }

    if (gadgetWord.size() > BPFJ_GLOB_MAP_MAX_GADGETS) {
      return err::Error(
          std::errc::argument_list_too_long, "Too many glob variables");
    }

    // Apply the leading-'*' epsilon closure to the initial state of each word.
    // (A leading ${NAME} bound to an empty value is closed per lookup.)
    for (__u32 w = 0; w < numWords; ++w) {
      initState[w] |= (initState[w] & starMask[w]) << 1;
    }

    if (auto res = store(
            numWords,
            patterns,
            charMask,
            starMask,
            initState,
            gadgetWord,
            gadgetBase,
            gadgetKey);
        !res) {
      return res;
    }

    headerGuard.dismiss();
    return err::unit;
  }

  // The arena header, as published to BPF; null until the first successful
  // init() and again after destroy().
  struct bpfj_glob_map* get() const {
    return hdr();
  }

  void destroy() {
    if (slot_ == nullptr || hdr() == nullptr) {
      return;
    }
    if (headerNumWords() != 0) {
      heap::free(skel_, headerCharMask());
      heap::free(skel_, headerStarMask());
      heap::free(skel_, headerInitState());
      if (headerNumAccepts() != 0) {
        heap::free(skel_, headerAcceptWord());
        heap::free(skel_, headerAcceptBit());
        heap::free(skel_, headerAcceptVal());
      }
      if (headerNumGadgets() != 0) {
        heap::free(skel_, headerGadgetWord());
        heap::free(skel_, headerGadgetBase());
        heap::free(skel_, headerGadgetKey());
      }
      if (headerNumVars() != 0) {
        heap::free(skel_, headerVarKeys());
      }
    }
    heap::free(skel_, hdr());
    *slot_ = nullptr;
  }

 private:
  struct Compiled {
    __u32 numBits = 0; // total width (excluding accept), incl. gadget widths
    __u64 starBits = 0; // bit i set if token at i is '*'
    std::array<__u64, 256> charBits{}; // charBits[c] bit i set if token i ~ c
    std::vector<std::pair<__u32, __u32>> gadgets; // (relative base bit, key)
  };

  struct CompiledPattern {
    __u32 word;
    __u32 acceptBit;
    __u64 val;
  };

  // The key for ${NAME}, refusing 0 since the BPF side reads a zeroed binding
  // slot as holding it.
  err::Expected<__u32> resolve(std::string_view name) const {
    if (!resolveKey_) {
      return err::Error(
          std::errc::invalid_argument,
          "Glob pattern references a variable but none are bound here");
    }

    auto key = resolveKey_(name);
    if (!key) {
      return key.error();
    }

    if (*key == 0) {
      return err::Error(
          std::errc::invalid_argument,
          "Glob variable resolved to the reserved key 0");
    }

    return key;
  }

  // Compile a pattern into per-bit contributions relative to bit 0, collapsing
  // consecutive '*' and reserving a BPFJ_GLOB_MAP_MAX_VAR_LEN-wide gadget per
  // ${NAME}.
  err::Expected<> compile(std::string_view pattern, Compiled& out) {
    bool lastWasStar = false;
    std::size_t i = 0;
    __u32 pos = 0;
    while (i < pattern.size()) {
      const char pc = pattern[i];

      // Backslash escape: the next character is matched literally (lets callers
      // embed '*', '?', '$' or '\\' in an otherwise-literal pattern).
      if (pc == '\\' && i + 1 < pattern.size()) {
        if (pos + 1 > BPFJ_GLOB_MAP_MAX_TOKENS) {
          return err::Error(
              std::errc::argument_list_too_long, "Glob pattern too long");
        }
        out.charBits[static_cast<unsigned char>(pattern[i + 1])] |= 1ULL << pos;
        ++pos;
        lastWasStar = false;
        i += 2;
        continue;
      }

      // ${NAME} variable reference.
      if (pc == '$' && i + 1 < pattern.size() && pattern[i + 1] == '{') {
        std::size_t end = pattern.find('}', i + 2);
        if (end == std::string_view::npos) {
          return err::Error(
              std::errc::invalid_argument,
              "Unterminated variable reference in glob pattern");
        }
        auto key = resolve(pattern.substr(i + 2, end - (i + 2)));
        if (!key) {
          return key.error();
        }
        if (pos + BPFJ_GLOB_MAP_MAX_VAR_LEN > BPFJ_GLOB_MAP_MAX_TOKENS) {
          return err::Error(
              std::errc::argument_list_too_long, "Glob pattern too long");
        }
        out.gadgets.emplace_back(pos, *key);
        pos += BPFJ_GLOB_MAP_MAX_VAR_LEN;
        lastWasStar = false;
        i = end + 1;
        continue;
      }

      if (pc == '*' && lastWasStar) {
        ++i;
        continue; // collapse consecutive stars
      }
      if (pos + 1 > BPFJ_GLOB_MAP_MAX_TOKENS) {
        return err::Error(
            std::errc::argument_list_too_long, "Glob pattern too long");
      }
      const __u64 bit = 1ULL << pos;
      if (pc == '*') {
        out.starBits |= bit;
        lastWasStar = true;
      } else if (pc == '?') {
        for (auto& cb : out.charBits) {
          cb |= bit;
        }
        lastWasStar = false;
      } else {
        out.charBits[static_cast<unsigned char>(pc)] |= bit;
        lastWasStar = false;
      }
      ++pos;
      ++i;
    }
    out.numBits = pos;
    return err::unit;
  }

  // Shift a pattern's bit-0-relative contributions to its assigned [word, base]
  // and OR them into the compiled tables.
  static void placePattern(
      std::vector<__u64>& charMask,
      std::vector<__u64>& starMask,
      std::vector<__u64>& initState,
      __u32 numWords,
      __u32 word,
      __u32 base,
      const Compiled& c) {
    for (int ch = 0; ch < 256; ++ch) {
      const __u64 bits = c.charBits[static_cast<std::size_t>(ch)];
      if (bits != 0) {
        charMask[(static_cast<std::size_t>(ch) * numWords) + word] |= bits
            << base;
      }
    }
    starMask[word] |= c.starBits << base;
    initState[word] |= 1ULL << base; // start state for this pattern
  }

  err::Expected<> store(
      __u32 numWords,
      const std::vector<CompiledPattern>& patterns,
      const std::vector<__u64>& charMask,
      const std::vector<__u64>& starMask,
      const std::vector<__u64>& initState,
      const std::vector<__u32>& gadgetWord,
      const std::vector<__u32>& gadgetBase,
      const std::vector<__u32>& gadgetKey) {
    // Empty map (no patterns): leave the header zeroed (num_words == 0). The
    // matcher reads this as "matches nothing" and destroy() is a no-op. Skip
    // the allocations entirely — a zero-size heap alloc returns null and would
    // look like an out-of-memory failure.
    if (numWords == 0) {
      clearHeader();
      return err::unit;
    }

    const __u32 numAccepts = static_cast<__u32>(patterns.size());
    const __u32 numGadgets = static_cast<__u32>(gadgetWord.size());
    // Published so a converter holding more variables than a lookup can bind
    // picks the ones these patterns use (bpfj_glob_map_wants_key).
    std::vector<__u32> varKeys(gadgetKey);
    std::sort(varKeys.begin(), varKeys.end());
    varKeys.erase(std::unique(varKeys.begin(), varKeys.end()), varKeys.end());
    const __u32 numVars = static_cast<__u32>(varKeys.size());
    // A lookup carries at most BPFJ_GLOB_MAP_MAX_BINDINGS bindings, so any key
    // past that could never be bound and its gadgets would silently match the
    // empty string.
    if (numVars > BPFJ_GLOB_MAP_MAX_BINDINGS) {
      return err::Error(
          std::errc::argument_list_too_long,
          "Too many distinct glob variables");
    }

    std::vector<__u32> acceptWord(numAccepts, 0);
    std::vector<__u32> acceptBit(numAccepts, 0);
    std::vector<__u64> acceptVal(numAccepts, 0);
    for (std::size_t i = 0; i < patterns.size(); ++i) {
      acceptWord[i] = patterns[i].word;
      acceptBit[i] = patterns[i].acceptBit;
      acceptVal[i] = patterns[i].val;
    }

    auto* charMaskArena = heap::allocArray<__u64>(skel_, charMask.size());
    auto* starMaskArena = heap::allocArray<__u64>(skel_, numWords);
    auto* initStateArena = heap::allocArray<__u64>(skel_, numWords);
    if (charMaskArena == nullptr || starMaskArena == nullptr ||
        initStateArena == nullptr) {
      heap::free(skel_, charMaskArena);
      heap::free(skel_, starMaskArena);
      heap::free(skel_, initStateArena);
      return err::Error(
          std::errc::not_enough_memory, "Failed to allocate glob map");
    }

    __u32* acceptWordArena = nullptr;
    __u32* acceptBitArena = nullptr;
    __u64* acceptValArena = nullptr;
    __u32* gadgetWordArena = nullptr;
    __u32* gadgetBaseArena = nullptr;
    __u32* gadgetKeyArena = nullptr;
    __u32* varKeysArena = nullptr;
    auto cleanup = [&]() {
      heap::free(skel_, charMaskArena);
      heap::free(skel_, starMaskArena);
      heap::free(skel_, initStateArena);
      heap::free(skel_, acceptWordArena);
      heap::free(skel_, acceptBitArena);
      heap::free(skel_, acceptValArena);
      heap::free(skel_, gadgetWordArena);
      heap::free(skel_, gadgetBaseArena);
      heap::free(skel_, gadgetKeyArena);
      heap::free(skel_, varKeysArena);
    };

    if (numAccepts != 0) {
      acceptWordArena = heap::allocArray<__u32>(skel_, numAccepts);
      acceptBitArena = heap::allocArray<__u32>(skel_, numAccepts);
      acceptValArena = heap::allocArray<__u64>(skel_, numAccepts);
      if (acceptWordArena == nullptr || acceptBitArena == nullptr ||
          acceptValArena == nullptr) {
        cleanup();
        return err::Error(
            std::errc::not_enough_memory, "Failed to allocate glob map");
      }
    }
    if (numGadgets != 0) {
      gadgetWordArena = heap::allocArray<__u32>(skel_, numGadgets);
      gadgetBaseArena = heap::allocArray<__u32>(skel_, numGadgets);
      gadgetKeyArena = heap::allocArray<__u32>(skel_, numGadgets);
      varKeysArena = heap::allocArray<__u32>(skel_, numVars);
      if (gadgetWordArena == nullptr || gadgetBaseArena == nullptr ||
          gadgetKeyArena == nullptr || varKeysArena == nullptr) {
        cleanup();
        return err::Error(
            std::errc::not_enough_memory, "Failed to allocate glob map");
      }
    }

    copyU64(charMaskArena, charMask);
    copyU64(starMaskArena, starMask);
    copyU64(initStateArena, initState);
    if (numAccepts != 0) {
      copyU32(acceptWordArena, acceptWord);
      copyU32(acceptBitArena, acceptBit);
      copyU64(acceptValArena, acceptVal);
    }
    if (numGadgets != 0) {
      copyU32(gadgetWordArena, gadgetWord);
      copyU32(gadgetBaseArena, gadgetBase);
      copyU32(gadgetKeyArena, gadgetKey);
      copyU32(varKeysArena, varKeys);
    }

    writeHeader(
        bpfj_glob_map{
            .char_mask = charMaskArena,
            .star_mask = starMaskArena,
            .init_state = initStateArena,
            .accept_word = acceptWordArena,
            .accept_bit = acceptBitArena,
            .accept_val = acceptValArena,
            .gadget_word = gadgetWordArena,
            .gadget_base = gadgetBaseArena,
            .gadget_key = gadgetKeyArena,
            .var_keys = varKeysArena,
            .num_words = numWords,
            .num_accepts = numAccepts,
            .num_gadgets = numGadgets,
            .num_vars = numVars,
        });
    return err::unit;
  }

  __attribute__((no_sanitize("address"))) static void copyU64(
      __u64* dst,
      const std::vector<__u64>& src) {
    for (std::size_t i = 0; i < src.size(); ++i) {
      dst[i] = src[i];
    }
  }

  __attribute__((no_sanitize("address"))) static void copyU32(
      __u32* dst,
      const std::vector<__u32>& src) {
    for (std::size_t i = 0; i < src.size(); ++i) {
      dst[i] = src[i];
    }
  }

  struct bpfj_glob_map* hdr() const {
    return *slot_;
  }

  // Copy a fully-populated header into the arena-backed map in one shot. Taking
  // the assembled struct (built with designated initializers at the call site)
  // instead of a long list of same-typed scalars/pointers keeps the fields
  // named and unswappable.
  __attribute__((no_sanitize("address"))) void writeHeader(
      const struct bpfj_glob_map& src) {
    *hdr() = src;
  }

  __attribute__((no_sanitize("address"))) void clearHeader() {
    hdr()->char_mask = nullptr;
    hdr()->star_mask = nullptr;
    hdr()->init_state = nullptr;
    hdr()->accept_word = nullptr;
    hdr()->accept_bit = nullptr;
    hdr()->accept_val = nullptr;
    hdr()->gadget_word = nullptr;
    hdr()->gadget_base = nullptr;
    hdr()->gadget_key = nullptr;
    hdr()->var_keys = nullptr;
    hdr()->num_words = 0;
    hdr()->num_accepts = 0;
    hdr()->num_gadgets = 0;
    hdr()->num_vars = 0;
  }

  __attribute__((no_sanitize("address"))) __u32 headerNumWords() const {
    return hdr()->num_words;
  }
  __attribute__((no_sanitize("address"))) __u32 headerNumAccepts() const {
    return hdr()->num_accepts;
  }
  __attribute__((no_sanitize("address"))) __u32 headerNumGadgets() const {
    return hdr()->num_gadgets;
  }
  __attribute__((no_sanitize("address"))) __u32 headerNumVars() const {
    return hdr()->num_vars;
  }
  __attribute__((no_sanitize("address"))) __u64* headerCharMask() {
    return hdr()->char_mask;
  }
  __attribute__((no_sanitize("address"))) __u64* headerStarMask() {
    return hdr()->star_mask;
  }
  __attribute__((no_sanitize("address"))) __u64* headerInitState() {
    return hdr()->init_state;
  }
  __attribute__((no_sanitize("address"))) __u32* headerAcceptWord() {
    return hdr()->accept_word;
  }
  __attribute__((no_sanitize("address"))) __u32* headerAcceptBit() {
    return hdr()->accept_bit;
  }
  __attribute__((no_sanitize("address"))) __u64* headerAcceptVal() {
    return hdr()->accept_val;
  }
  __attribute__((no_sanitize("address"))) __u32* headerGadgetWord() {
    return hdr()->gadget_word;
  }
  __attribute__((no_sanitize("address"))) __u32* headerGadgetBase() {
    return hdr()->gadget_base;
  }
  __attribute__((no_sanitize("address"))) __u32* headerGadgetKey() {
    return hdr()->gadget_key;
  }
  __attribute__((no_sanitize("address"))) __u32* headerVarKeys() {
    return hdr()->var_keys;
  }

  std::shared_ptr<Skel> skel_;
  // Where the caller wants the arena header pointer recorded.
  struct bpfj_glob_map** slot_ = nullptr;
  bool checkDestroy_ = true;
  GlobKeyResolver resolveKey_;
};

} // namespace bpfjailer
