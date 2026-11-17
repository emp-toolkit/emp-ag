#ifndef EMP_AG_H__
#define EMP_AG_H__

// emp-ag: AGMPC authenticated garbling for n >= 2 parties (KRRW), built on
// emp-tool's BooleanContext + session model. The protocol is mpc by default
// (AGMPCSession<nP>); the 2-party case is just AGMPCSession<2> — the nP==2
// instantiation, special-cased only where the algebra collapses (the c_gamma equality
// fold, the streamlined 2-party leaky-AND, the one-garbler garble path). There is no
// separate 2pc session. Circuits are authored in emp-tool's typed.h value model over
// the session's gate context:
//
//   AGMPCSession<nP> sess(io, &pool, party);   // nP==2 for two-party
//   using UInt32 = UInt_T<AGMPCSession<nP>::ctx_t, 32>;
//   auto a   = sess.input<UInt32>(/*owner party*/1, x);   // authenticated input
//   auto out = sess.reveal(a + b, PUBLIC);                // std::optional
//
// Expert / backend users include emp-ag/backend/*.h directly.

#include "emp-tool/emp-tool.h"
#include "emp-ag/frontend/agmpc_session.h"   // AGMPCSession (ctx_t = emp-tool ChunkRecorderCtx)

#endif  // EMP_AG_H__
