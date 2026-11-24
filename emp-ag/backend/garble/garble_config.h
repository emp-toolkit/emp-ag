#ifndef EMP_AG_BACKEND_GARBLE_GARBLE_CONFIG_H__
#define EMP_AG_BACKEND_GARBLE_GARBLE_CONFIG_H__
//
// The options of a session, fixed at compile time: AGMPCSession<nP, Cfg> and everything
// below it take a GarbleConfig Cfg, which sets how the garbling runs (Auth, Delivery) and
// which COT streams make the aShares (Cot, and SilentFerret's LPN set FerretLpn,
// ashare/cot.h). The garbled rows do not vary:
// half-gates for each garbler's own label and three rows toward every other garbler.
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
#include "emp-ag/backend/ashare/cot.h"   // Cot
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

template <Auth A = Auth::EMP_AG_GARBLE_AUTH, Delivery D = Delivery::EMP_AG_GARBLE_DELIVERY,
          Cot C = Cot::EMP_AG_COT, FerretLpn L = FerretLpn::B12>
struct GarbleConfig {
  static constexpr Auth auth = A;
  static constexpr Delivery delivery = D;
  static constexpr Cot cot = C;
  static constexpr FerretLpn lpn = L;
};

// The session id a party runs under: the given one for the default, KRRW with the ring
// over SoftSpoken, so the default transcript does not depend on the options; otherwise
// one bound to the options. The delivery does not count at nP = 2, where both choices are
// the same, nor the LPN set on SoftSpoken streams.
template <int nP, class Cfg>
inline block bind_garble_config(block session_id) {
  const bool ring = nP == 2 || Cfg::delivery == Delivery::RING;
  if (Cfg::auth == Auth::KRRW && ring && Cfg::cot == Cot::SoftSpoken) return session_id;
  RO ro("emp-ag:garble-config", session_id);
  ro.absorb((uint64_t)Cfg::auth).absorb((uint64_t)(ring ? Delivery::RING : Delivery::DIRECT));
  if (Cfg::cot != Cot::SoftSpoken) ro.absorb((uint64_t)Cfg::cot);
  if (Cfg::cot == Cot::SilentFerret && Cfg::lpn != FerretLpn::B12) ro.absorb((uint64_t)Cfg::lpn);
  return ro.squeeze_block();
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_GARBLE_GARBLE_CONFIG_H__
