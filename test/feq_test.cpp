#include "emp-ag/backend/crypto/feq.h"
#include "emp-ag/backend/crypto/protocols.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

// Exercise the production opening path over a local socket pair. The peer's
// commitment/nonce are supplied independently so each binding can be attacked.
static void opening_case(int party, int attack) {
  using namespace emp;
  using namespace emp::ag;
  int fd[2];
  expecting(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0, "feq test: socketpair");
  NetIO local(fd[0], true), peer(fd[1], true);
  const block sid = makeBlock(101, 103), seed = makeBlock(107, 109);
  PRG prg(&seed);
  char digest[FsHash::DIGEST_SIZE], peer_digest[FsHash::DIGEST_SIZE];
  FsHash::hash_once(digest, "nonce-only equality", 19);
  std::memcpy(peer_digest, digest, sizeof(digest));
  auto state = feq_prepare_symmetric_2pc(&prg, sid, "emp-ag:laand", party, digest);
  block peer_nonce = makeBlock(113, 127), peer_sid = sid;
  int peer_role = 3 - party;
  const char* peer_purpose = "emp-ag:laand";
  if (attack == 1) peer_digest[0] ^= 1;  // unequal inputs
  if (attack == 3) peer_role = party;   // wrong role
  if (attack == 4) peer_sid ^= bit0_mask;
  if (attack == 5) peer_purpose = "emp-ag:cgamma";
  char commitment[FsHash::DIGEST_SIZE];
  feq_symmetric_commitment_2pc(commitment, peer_sid, peer_purpose,
                               peer_role, peer_digest, peer_nonce);
  if (attack == 2) peer_nonce ^= bit0_mask; // nonce changed after commitment
  if (attack == 6) {                       // reflect our commitment/opening
    std::memcpy(commitment, state.commitment, sizeof(commitment));
    peer_nonce = state.nonce;
  }
  if (attack == 7) commitment[0] ^= 1;

  // Both commitments are fixed before the production opening is invoked.
  local.send_data(state.commitment, sizeof(state.commitment));
  local.flush();
  peer.send_data(commitment, sizeof(commitment));
  peer.send_block(&peer_nonce, 1);
  peer.flush();
  local.recv_data(state.peer_commitment, sizeof(state.peer_commitment));
  feq_finish_symmetric_2pc(&local, &local, sid, "emp-ag:laand", party,
                           state, "feq test: opening rejected");

  char received_commitment[FsHash::DIGEST_SIZE];
  block received_nonce;
  peer.recv_data(received_commitment, sizeof(received_commitment));
  peer.recv_block(&received_nonce, 1);
  expecting(std::memcmp(received_commitment, state.commitment,
                         sizeof(received_commitment)) == 0 &&
            cmpBlock(&received_nonce, &state.nonce, 1), "feq test: opening changed");
  expecting(local.send_counter == 48 && local.recv_counter == 48 &&
            peer.send_counter == 48 && peer.recv_counter == 48,
            "feq test: equality must use 96 bytes in total");
}

static bool rejects_opening(int party, int attack) {
  std::fflush(nullptr);
  const pid_t child = fork();
  emp::expecting(child >= 0, "feq test: fork");
  if (child == 0) {
    std::freopen("/dev/null", "w", stderr);
    opening_case(party, attack);
    std::_Exit(0);
  }
  int status;
  emp::expecting(waitpid(child, &status, 0) == child, "feq test: waitpid");
  return WIFEXITED(status) && WEXITSTATUS(status) == 1;
}

int main() {
  using namespace emp;
  using namespace emp::ag;

  const block sid = makeBlock(1, 2);
  const block nonce = makeBlock(3, 4);
  char digest[FsHash::DIGEST_SIZE];
  FsHash::hash_once(digest, "F_eq reflection test", 20);

  char p1[FsHash::DIGEST_SIZE], p1_again[FsHash::DIGEST_SIZE];
  char p2[FsHash::DIGEST_SIZE], other_sid[FsHash::DIGEST_SIZE];
  char other_purpose[FsHash::DIGEST_SIZE];
  feq_symmetric_commitment_2pc(p1, sid, "emp-ag:laand", 1, digest, nonce);
  feq_symmetric_commitment_2pc(p1_again, sid, "emp-ag:laand", 1, digest, nonce);
  feq_symmetric_commitment_2pc(p2, sid, "emp-ag:laand", 2, digest, nonce);
  feq_symmetric_commitment_2pc(other_sid, makeBlock(1, 3), "emp-ag:laand", 1,
                               digest, nonce);
  feq_symmetric_commitment_2pc(other_purpose, sid, "emp-ag:cgamma", 1, digest,
                               nonce);

  block lane_digest[2][2] = {
      {makeBlock(10, 11), makeBlock(12, 13)},
      {makeBlock(14, 15), makeBlock(16, 17)}};
  auto lane_coin = [&](block lane_sid) {
    return fs_coin_lane_set(
        "emp-ag:test-lanes", lane_sid, 2,
        [&](int lane, int direction) { return lane_digest[lane][direction]; });
  };
  const block lanes0 = lane_coin(sid);
  lane_digest[1][1] ^= makeBlock(0, 1);
  const block lanes1 = lane_coin(sid);
  const block lanes_other_sid = lane_coin(makeBlock(1, 3));

  const block commit_payload[2] = {makeBlock(21, 22), makeBlock(23, 24)};
  char role1[FsHash::DIGEST_SIZE], role1_again[FsHash::DIGEST_SIZE];
  char role2[FsHash::DIGEST_SIZE], role_other_sid[FsHash::DIGEST_SIZE];
  char role_other_purpose[FsHash::DIGEST_SIZE];
  role_bound_commitment(role1, sid, "emp-ag:test-commit", 1,
                        commit_payload, sizeof(commit_payload));
  role_bound_commitment(role1_again, sid, "emp-ag:test-commit", 1,
                        commit_payload, sizeof(commit_payload));
  role_bound_commitment(role2, sid, "emp-ag:test-commit", 2,
                        commit_payload, sizeof(commit_payload));
  role_bound_commitment(role_other_sid, makeBlock(1, 3),
                        "emp-ag:test-commit", 1,
                        commit_payload, sizeof(commit_payload));
  role_bound_commitment(role_other_purpose, sid, "emp-ag:test-other", 1,
                        commit_payload, sizeof(commit_payload));

  bool ok =
      memcmp(p1, p1_again, FsHash::DIGEST_SIZE) == 0 &&
      memcmp(p1, p2, FsHash::DIGEST_SIZE) != 0 &&
      memcmp(p1, other_sid, FsHash::DIGEST_SIZE) != 0 &&
      memcmp(p1, other_purpose, FsHash::DIGEST_SIZE) != 0 &&
      !cmpBlock(&lanes0, &lanes1, 1) &&
      !cmpBlock(&lanes1, &lanes_other_sid, 1) &&
      memcmp(role1, role1_again, FsHash::DIGEST_SIZE) == 0 &&
      memcmp(role1, role2, FsHash::DIGEST_SIZE) != 0 &&
      memcmp(role1, role_other_sid, FsHash::DIGEST_SIZE) != 0 &&
      memcmp(role1, role_other_purpose, FsHash::DIGEST_SIZE) != 0;
  for (int party : {1, 2}) {
    opening_case(party, 0);
    for (int attack = 1; attack <= 7; ++attack)
      ok = rejects_opening(party, attack) && ok;
  }
  std::printf("feq_test: %s\n", ok ? "GOOD!" : "BAD!");
  return ok ? 0 : 1;
}
