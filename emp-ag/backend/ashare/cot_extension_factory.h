#ifndef EMP_AG_BACKEND_ASHARE_COT_EXTENSION_FACTORY_H__
#define EMP_AG_BACKEND_ASHARE_COT_EXTENSION_FACTORY_H__
//
// COT streams an application supplies to a session, in place of emp-ag's own SoftSpoken
// streams (softspoken_mint.h). Each unordered pair of parties has two directed streams.
// The higher-numbered party sends on the pair's primary stream, which runs its own base
// OTs; the reverse stream runs over 128 base OTs that emp-ag derives from the primary's
// first 128 COTs once they are checked. A factory builds the two streams; emp-ag does
// everything around them: each direction's session id (set_sid), the sender's Delta
// (set_delta, the session's global key), the counted begin(n) when the session has a
// plan, drawing and check()ing the 128-COT prefix, the derivation, and the consistency
// check before any reveal.
//
// So a factory's streams must
//   1. be maliciously secure random COTs whose check() is their consistency check and
//      aborts on failure;
//   2. honor set_sid and set_delta;
//   3. draw each receiver's choice bits as its own fresh, private randomness, which the
//      reverse derivation rests on;
//   4. honor begin(n) and draw in order, so that both ends of a stream stay in step.
// The id names the construction and its parameters. A session binds a nonempty id into
// its session id before setup (bind_cot_extension), so parties that chose different
// streams fail setup. The default, emp-ag's own streams, has the empty id and leaves the
// session id unchanged. Supplied streams need the SoftSpoken mint and run on one lane:
// further lanes would be clones of a SoftSpoken stream.
//
#include "emp-ot/emp-ot.h"                  // OT, OTExtension
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/core/error.h"
#include "emp-tool/runtime/crypto/ro.h"
#include "emp-tool/runtime/io/net_io_channel.h"
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

struct CotExtensionFactory {
  std::string id;
  // A pair's primary stream, in role ALICE (sender) or BOB (receiver) on channel ch, with
  // its own base OTs.
  std::function<std::unique_ptr<OTExtension>(int role, NetIO *ch)> primary;
  // A pair's reverse stream, in role ALICE or BOB on channel ch, over `base`: the 128 OTs
  // emp-ag derived from the primary's checked prefix.
  std::function<std::unique_ptr<OTExtension>(int role, NetIO *ch, std::unique_ptr<OT> base)>
      reverse;

  // Whether it supplies streams (otherwise the session uses its own).
  bool supplied() const { return (bool)primary || (bool)reverse; }
};

// Aborts unless the factory is empty (the session's own streams) or complete: both
// constructors and an id.
inline void validate_cot_extension_factory(const CotExtensionFactory &f) {
  if (!f.supplied()) {
    expecting(f.id.empty(), "COT streams: an id without constructors");
    return;
  }
  expecting((bool)f.primary && (bool)f.reverse,
            "COT streams: a supplied factory needs both a primary and a reverse constructor");
  expecting(!f.id.empty(), "COT streams: a supplied factory needs an id");
}

// The session id under the COT streams `id` names: unchanged for the empty id.
inline block bind_cot_extension(block session_id, const std::string &id) {
  if (id.empty()) return session_id;
  return RO("emp-ag:cot-extension", session_id).absorb(std::string_view(id)).squeeze_block();
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_ASHARE_COT_EXTENSION_FACTORY_H__
