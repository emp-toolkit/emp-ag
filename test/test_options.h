#ifndef EMP_AG_TEST_TEST_OPTIONS_H__
#define EMP_AG_TEST_TEST_OPTIONS_H__
//
// A test's protocol options (ag::ProtocolOptions), from its arguments (test_args.h):
//   delivery=ring|direct            how the garblers' rows reach P1
//   open_check=pairwise|symmetric   the open checker
//   cnc=<batch>                     cut-and-choose triples, generated <batch> at a time
//   tag_bytes=<10..16>              share evaluation's tag width
// An option no argument names keeps the build's default. A test that takes them adds
// TEST_OPTION_ARGS to the argument names it lists.
//
#include "emp-ag/backend/garble/garble_config.h"   // ProtocolOptions
#include "test_args.h"
#include <string>

#define TEST_OPTION_ARGS "delivery", "open_check", "cnc", "tag_bytes"

inline emp::ag::ProtocolOptions test_options(const TestArgs &args) {
  emp::ag::ProtocolOptions o;
  const std::string delivery = args.str("delivery", "");
  if (delivery == "ring") o.delivery = emp::ag::Delivery::RING;
  else if (delivery == "direct") o.delivery = emp::ag::Delivery::DIRECT;
  else emp::expecting(delivery.empty(), "test: delivery is ring or direct");
  const std::string check = args.str("open_check", "");
  if (check == "pairwise") o.open_check = emp::ag::OpenCheckKind::Pairwise;
  else if (check == "symmetric") o.open_check = emp::ag::OpenCheckKind::Symmetric;
  else emp::expecting(check.empty(), "test: open_check is pairwise or symmetric");
  o.cut_and_choose_batch = args.num("cnc", o.cut_and_choose_batch);
  o.share_tag_bytes = (int)args.num("tag_bytes", o.share_tag_bytes);
  return o;
}

#endif  // EMP_AG_TEST_TEST_OPTIONS_H__
