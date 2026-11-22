#ifndef EMP_AG_BACKEND_ASHARE_COT_H__
#define EMP_AG_BACKEND_ASHARE_COT_H__
//
// The COT streams behind the share generator (ashare_gen.h): one SoftSpoken extension per
// peer and direction (softspoken_mint.h), or one SilentFerret instance per peer and
// direction with every stream's LPN step applied in one pass (silent_ferret_mint.h). A
// session takes the choice with its compile-time options (GarbleConfig's Cot, which binds
// a non-default choice into the session id); -DEMP_AG_COT=<SoftSpoken|SilentFerret>
// changes the default for a whole build.
//
#include <cstdint>

namespace emp::ag {

enum class Cot : uint8_t { SoftSpoken, SilentFerret };

#ifndef EMP_AG_COT
#define EMP_AG_COT SoftSpoken
#endif

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_ASHARE_COT_H__
