// Non-network unit test of the direct-chunk flush planner (emp::session::plan_flush):
// DCE, RecordCtx-canonical compaction, and stale-operand detection. Pure graph logic
// — no protocol, no sockets — so the trickiest direct-chunk code is covered directly
// (the multi-party tests can only exercise it indirectly, and the stale-id guard's
// expecting() -> _Exit(1) can't be death-tested in a live run). The planner lives in the
// shared ChunkedSession foundation, so this is session-agnostic; it runs here against
// the AGMPCSession include.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdio>
#include <vector>
using namespace emp;
using emp::circuit::Gate;
using emp::circuit::Op;

int main() {
  bool ok = true;

  // Recorder id 0 is the null sentinel, so the chunks below start at id 1.
  // 1) Basic compaction: ids 1,2 materialized; gate 3 = AND(1,2) kept.
  {
    std::vector<Gate> chunk = {{1, 2, 3, Op::And}};
    auto p = emp::session::plan_flush(chunk, {3}, [](uint32_t id) { return id == 1 || id == 2; });
    bool good = p.ok && p.prog.num_inputs == 2 && p.prog.gates.size() == 1 &&
                p.prog.gates[0].out == 2 &&            // canonical: num_inputs + 0
                p.input_ids.size() == 2 && p.output_ids.size() == 1 &&
                p.output_ids[0] == 3 && p.prog.outputs.size() == 1;
    printf("  basic compaction: %s\n", good ? "GOOD!" : "BAD!"); ok &= good;
  }

  // 2) DCE: ids 1,2,3 materialized; gate 4=AND(1,2) kept, gate 5=AND(1,3) dead.
  //    The dead gate and its private operand (3) are dropped.
  {
    std::vector<Gate> chunk = {{1, 2, 4, Op::And}, {1, 3, 5, Op::And}};
    auto p = emp::session::plan_flush(chunk, {4}, [](uint32_t id) { return id >= 1 && id <= 3; });
    bool good = p.ok && p.prog.gates.size() == 1 && p.output_ids.size() == 1 &&
                p.output_ids[0] == 4 && p.input_ids.size() == 2;   // inputs 1,2 only
    printf("  dead-code elimination: %s\n", good ? "GOOD!" : "BAD!"); ok &= good;
  }

  // 3) Stale operand: gate references id 9, neither chunk-local nor materialized.
  {
    std::vector<Gate> chunk = {{1, 9, 2, Op::And}};
    auto p = emp::session::plan_flush(chunk, {2}, [](uint32_t id) { return id == 1; });
    bool good = !p.ok;
    printf("  stale-operand detection: %s\n", good ? "GOOD!" : "BAD!"); ok &= good;
  }

  // 4) Const-only program: a kept Const1 with no inputs.
  {
    std::vector<Gate> chunk = {{0, 0, 5, Op::Const1}};
    auto p = emp::session::plan_flush(chunk, {5}, [](uint32_t) { return false; });
    bool good = p.ok && p.prog.num_inputs == 0 && p.prog.gates.size() == 1 &&
                p.prog.outputs.size() == 1 && p.output_ids.size() == 1;
    printf("  const-only program: %s\n", good ? "GOOD!" : "BAD!"); ok &= good;
  }

  printf("agmpc_flush_plan: %s\n", ok ? "GOOD!" : "BAD!");
  return ok ? 0 : 1;
}
