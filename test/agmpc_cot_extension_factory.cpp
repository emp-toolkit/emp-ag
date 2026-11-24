// A session over COT streams the application supplies (ag::CotExtensionFactory): here
// SoftSpoken over a BMM base OT for each pair's primary stream, in place of the default
// CSW, and SoftSpoken over the derived base OTs for the reverse. The factory builds each
// party's two streams per peer, its id is bound into the session id, and the session
// computes correctly over the streams.
//
// The case=<n> argument (test_args.h) selects a misuse the session must refuse instead: 1 asks for two lanes
// (supplied streams run on one), 2 leaves the id empty, 3 supplies primary sender streams
// that keep a Delta of their own in place of the one they are given.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "test_args.h"
#include "emp-ot/base_ot/base_ot_select.h"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <memory>
using namespace emp;

#ifndef COT_FACTORY_NP
#define COT_FACTORY_NP 2
#endif
static const int nP = COT_FACTORY_NP;
// The supplied streams need the SoftSpoken mint, whatever the build's default.
using Cfg = ag::GarbleConfig<ag::Auth::EMP_AG_GARBLE_AUTH, ag::Delivery::EMP_AG_GARBLE_DELIVERY,
                             ag::Cot::SoftSpoken>;
using AgSession = AGMPCSession<nP, Cfg>;
using UInt32 = UInt_T<AgSession::ctx_t, 32>;

// case=3: a sender stream that flips one bit of the Delta it is given.
struct OwnDelta final : ag::SoftSpokenCot {
  using ag::SoftSpokenCot::SoftSpokenCot;
  void set_delta(const bool *bits) override {
    bool own[128];
    std::copy(bits, bits + 128, own);
    own[5] = !own[5];
    ag::SoftSpokenCot::set_delta(own);
  }
};

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  const int port = peer_port();
  if (party > nP) return 0;
  const int cot_case = (int)TestArgs(argc, argv, {"case"}).num("case", 0);

  std::atomic<int> primaries{0}, reverses{0};
  ag::CotExtensionFactory cot;
  cot.id = cot_case == 2 ? "" : "test:softspoken-over-bmm";
  cot.primary = [&](int role, NetIO *ch) -> std::unique_ptr<OTExtension> {
    ++primaries;
    if (cot_case == 3 && role == ALICE)
      return std::make_unique<OwnDelta>(role, ch, /*malicious=*/true, make_base_ot(BaseOtKind::BMM, ch));
    return std::make_unique<ag::SoftSpokenCot>(role, ch, /*malicious=*/true,
                                               make_base_ot(BaseOtKind::BMM, ch));
  };
  cot.reverse = [&](int role, NetIO *ch, std::unique_ptr<OT> base) -> std::unique_ptr<OTExtension> {
    ++reverses;
    return std::make_unique<ag::SoftSpokenCot>(role, ch, /*malicious=*/true, std::move(base));
  };

  ThreadPool pool(ag::default_pool_size(nP));
  const block given = makeBlock(0x636f74ULL, 0x666163746f7279ULL);
  if (cot_case == 1) {
    AgSession sess(party, port, nullptr, &pool, 40, /*lanes=*/2, given, BaseOtKind::CSW, -1, -1,
                   {}, cot);
    return 1;   // unreachable: the session refuses two lanes
  }

  NetIOMP<nP> io(party, port);
  const uint32_t A = 0x12345678u, B = 0x9abcdef0u;
  bool ok = true;
  {
    AgSession sess(&io, &pool, party, 40, nullptr, given, BaseOtKind::CSW, -1, -1, {}, cot);
    // Every party builds one primary and one reverse stream per peer.
    expecting(primaries == nP - 1 && reverses == nP - 1,
              "agmpc_cot_extension_factory: the factory did not build every stream");
    const block options = ag::bind_build_options<nP, Cfg>(ag::bind_garble_config<nP, Cfg>(given));
    const block want =
        ag::bind_cot_extension(ag::bind_and_prep(options, ag::default_and_prep<nP>().id), cot.id);
    const block kept = sess.protocol().session_id;
    expecting(cmpBlock(&kept, &want, 1),
              "agmpc_cot_extension_factory: the factory's id is not bound into the session id");
    auto a = sess.input<UInt32>(1, party == 1 ? A : 0u);
    auto b = sess.input<UInt32>(nP, party == nP ? B : 0u);
    auto r = sess.reveal((a & b) + (a ^ b), 1);
    if (party == 1)
      ok = r.has_value() && (uint32_t)r.value() == (uint32_t)((A & B) + (A ^ B));
  }
  if (party == 1) std::printf("agmpc_cot_extension_factory np=%d: %s\n", nP, ok ? "GOOD!" : "BAD!");
  return ok ? 0 : 1;
}
