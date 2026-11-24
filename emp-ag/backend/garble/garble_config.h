#ifndef EMP_AG_BACKEND_GARBLE_GARBLE_CONFIG_H__
#define EMP_AG_BACKEND_GARBLE_GARBLE_CONFIG_H__
//
// The options of a session. AGMPCSession<nP, Cfg> and everything below it take a
// GarbleConfig Cfg, which fixes at compile time which COT streams make the aShares (Cot,
// and SilentFerret's LPN set FerretLpn, ashare/cot.h) and sets the defaults of the options
// chosen at run time (ProtocolOptions below): how the garbling runs (Auth, Delivery), the
// open checker, share evaluation's tags and the AND gates' protocol. The garbled rows do
// not vary: half-gates for each garbler's own label and three rows toward every other
// garbler.
//
// Auth: how P1's masked values Lambda are authenticated.
//   KRRW  P2 sends one extra bit per AND gate and P1 reads Lambda off it. After
//         evaluation P1 broadcasts every AND gate's Lambda and all parties run one
//         check over them (KRRW18's technique; garble/passes/mask_witness.h).
//   WRK   Every garbler also sends P1 the three rows it sends another garbler, under
//         P1's key and truncated to rho + 2 bits. P1 recovers from them the MAC on
//         the garblers' share of Lambda and checks it at every gate (WRK17's
//         technique on half-gate rows, as in DILO22). Nothing runs after evaluation
//         except handing the run's output Lambda to the garblers. Each party checks
//         only what it uses: P1 every gate, with soundness 2^-rho per attempt and one
//         attempt per aborted run; a garbler the Lambda of the outputs, against its
//         own labels. An honest party sees another's abort as a closed connection.
// Delivery (nP >= 3; at nP = 2 the single garbler sends to P1 either way): how the
// garblers' rows reach P1.
//   RING    Each garbler adds its rows into a running sum and passes it to the next;
//           the last sends P1 three rows per garbler.
//   DIRECT  Each garbler sends its own rows to P1, which sums them.
//
// -DEMP_AG_GARBLE_AUTH=<KRRW|WRK>, -DEMP_AG_GARBLE_DELIVERY=<RING|DIRECT> and
// -DEMP_AG_COT=<SoftSpoken|SilentFerret> change the default for a whole build. Every party must use the same options: a session binds
// any non-default choice into its session id (bind_garble_config below), so a mismatch
// fails setup.
//
#include "emp-ag/backend/ashare/cot.h"          // Cot
#include "emp-ag/backend/ashare/open_check.h"   // OpenCheckKind, EMP_AG_SHARE_TAG_BYTES
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/crypto/ro.h"
#include <cstdint>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

enum class Auth : uint8_t { KRRW, WRK };
enum class Delivery : uint8_t { RING, DIRECT };

#ifndef EMP_AG_GARBLE_AUTH
#define EMP_AG_GARBLE_AUTH KRRW
#endif
#ifndef EMP_AG_GARBLE_DELIVERY
#define EMP_AG_GARBLE_DELIVERY RING
#endif

// The build's default AND-gate protocol: the leaky ANDs, or cut-and-choose triples
// generated <batch> at a time under -DEMP_AG_CUT_AND_CHOOSE_BATCH=<batch>.
#ifdef EMP_AG_CUT_AND_CHOOSE_BATCH
inline constexpr int64_t kBuildCutAndChooseBatch = EMP_AG_CUT_AND_CHOOSE_BATCH;
#else
inline constexpr int64_t kBuildCutAndChooseBatch = 0;
#endif

// The options a session runs with, chosen at run time. Every party must choose them alike:
// a session binds each one that is not the default into its session id
// (bind_build_options, garble/protocol.h), so parties that chose differently fail setup.
// The build macros set the defaults.
struct ProtocolOptions {
  // How the garblers' rows reach P1 at nP >= 3 (Delivery above).
  Delivery delivery = Delivery::EMP_AG_GARBLE_DELIVERY;
  // The open checker of the AND gates' protocol (ashare/open_check.h).
  OpenCheckKind open_check = kBuildOpenCheck;
  // The width, in bytes, of share evaluation's tags (triple/share_eval.h): 10 to 16.
  int share_tag_bytes = EMP_AG_SHARE_TAG_BYTES;
  // The AND gates' protocol of a session given none: the leaky ANDs (0), or cut-and-choose
  // triples generated this many at a time (triple/cut_and_choose_triples.h).
  int64_t cut_and_choose_batch = kBuildCutAndChooseBatch;
};

inline void validate_protocol_options(const ProtocolOptions &o) {
  expecting(o.delivery == Delivery::RING || o.delivery == Delivery::DIRECT,
            "ProtocolOptions: an unknown delivery");
  expecting(o.open_check == OpenCheckKind::Default || o.open_check == OpenCheckKind::Pairwise ||
                o.open_check == OpenCheckKind::Symmetric,
            "ProtocolOptions: an unknown open checker");
  expecting(o.share_tag_bytes >= 10 && o.share_tag_bytes <= 16,
            "ProtocolOptions: share_tag_bytes must be 10 to 16");
  expecting(o.cut_and_choose_batch >= 0, "ProtocolOptions: a negative cut-and-choose batch");
}

template <Auth A = Auth::EMP_AG_GARBLE_AUTH, Delivery D = Delivery::EMP_AG_GARBLE_DELIVERY,
          Cot C = Cot::EMP_AG_COT, FerretLpn L = FerretLpn::B12>
struct GarbleConfig {
  static constexpr Auth auth = A;
  static constexpr Delivery delivery = D;
  static constexpr Cot cot = C;
  static constexpr FerretLpn lpn = L;
};

// The options a session of configuration Cfg runs with unless it is given others: the
// build's defaults, with Cfg's own choices. Options given to a session replace these, so
// to change one option of Cfg's, start from default_options<Cfg>().
template <class Cfg>
inline ProtocolOptions default_options() {
  ProtocolOptions o;
  o.delivery = Cfg::delivery;
  return o;
}

// The session id a party runs under: the given one for the default, KRRW with the ring
// over SoftSpoken, so the default transcript does not depend on the options; otherwise
// one bound to the options. The delivery does not count at nP = 2, where both choices are
// the same, nor the LPN set on SoftSpoken streams.
template <int nP>
inline block bind_garble_options(block session_id, Auth auth, Delivery delivery, Cot cot,
                                 FerretLpn lpn) {
  const bool ring = nP == 2 || delivery == Delivery::RING;
  if (auth == Auth::KRRW && ring && cot == Cot::SoftSpoken) return session_id;
  RO ro("emp-ag:garble-config", session_id);
  ro.absorb((uint64_t)auth).absorb((uint64_t)(ring ? Delivery::RING : Delivery::DIRECT));
  if (cot != Cot::SoftSpoken) ro.absorb((uint64_t)cot);
  if (cot == Cot::SilentFerret && lpn != FerretLpn::B12) ro.absorb((uint64_t)lpn);
  return ro.squeeze_block();
}

// The same, for the options of Cfg itself.
template <int nP, class Cfg>
inline block bind_garble_config(block session_id) {
  return bind_garble_options<nP>(session_id, Cfg::auth, Cfg::delivery, Cfg::cot, Cfg::lpn);
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_GARBLE_GARBLE_CONFIG_H__
