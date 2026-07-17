/**
 * AnonEcho — JavaScript wrapper for contract.compact
 * Midnight Hackathon submission
 *
 * What this does:
 *   1. Holds a user's group-credential secret key privately (never sent
 *      anywhere in cleartext).
 *   2. Builds the same Merkle-tree-of-members structure the contract's
 *      `memberTree` ledger keeps, so we can generate an inclusion path
 *      locally (this is exactly what a real Midnight wallet/prover does
 *      with the private witness data before proving).
 *   3. Generates a zero-knowledge proof for the `submitFeedback` circuit
 *      and "submits" it — i.e. produces the public transaction payload
 *      that would be sent to the network.
 *
 * Two modes, same call sites:
 *   - LOCAL SIMULATION (default, no setup): runs entirely in-process so
 *     you can demo the flow with `node index.js` at a hackathon with zero
 *     network/proof-server dependencies. Hashing stands in for the real
 *     proving system.
 *   - REAL NETWORK (commented, `wireRealMidnightProviders`): shows exactly
 *     where to plug in the actual `@midnight-ntwrk/midnight-js-*` provider
 *     stack once you have a compiled contract + running proof server.
 *
 * Swap SIMULATE_ZK_LAYER to false and fill in wireRealMidnightProviders()
 * once you've run `compactc contract.compact` and have a deployed address.
 */

'use strict';

const crypto = require('crypto');

const SIMULATE_ZK_LAYER = true;
const NULLIFIER_DOMAIN_TAG = 'ANONECHO_FEEDBACK_V1';
const MEMBER_TREE_DEPTH = 16; // must match contract.compact

// ---------------------------------------------------------------------------
// Small crypto helpers standing in for the contract's persistentHash<T>.
// ---------------------------------------------------------------------------

function sha256(...parts) {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function randomSecretKey() {
  return crypto.randomBytes(32);
}

function commitmentOf(secretKeyBuf) {
  // Mirrors: persistentHash<Bytes<32>>(secretKey)
  return sha256(secretKeyBuf);
}

function nullifierOf(secretKeyBuf) {
  // Mirrors: persistentHash<[Bytes<32>, Bytes<32>]>([secretKey, pad(32, tag)])
  const tag = Buffer.alloc(32);
  Buffer.from(NULLIFIER_DOMAIN_TAG).copy(tag);
  return sha256(secretKeyBuf, tag);
}

// ---------------------------------------------------------------------------
// Minimal fixed-depth Merkle tree mirroring the contract's `memberTree`
// ledger. In production this state lives on-chain; here we rebuild it
// client-side from the same registrations to derive an inclusion path.
// ---------------------------------------------------------------------------

class MemberMerkleTree {
  constructor(depth = MEMBER_TREE_DEPTH) {
    this.depth = depth;
    this.leaves = [];
  }

  insert(commitmentBuf) {
    const index = this.leaves.length;
    this.leaves.push(commitmentBuf);
    return index;
  }

  _levels() {
    let level = this.leaves.length ? [...this.leaves] : [Buffer.alloc(32)];
    const levels = [level];
    for (let d = 0; d < this.depth; d++) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = level[i + 1] ?? left; // duplicate last node if odd
        next.push(sha256(left, right));
      }
      level = next.length ? next : [Buffer.alloc(32)];
      levels.push(level);
      if (level.length === 1) break;
    }
    return levels;
  }

  root() {
    const levels = this._levels();
    return levels[levels.length - 1][0];
  }

  /** Inclusion path for the leaf at `index`: sibling hashes bottom-up. */
  pathFor(index) {
    const levels = this._levels();
    const siblings = [];
    let idx = index;
    for (let d = 0; d < levels.length - 1; d++) {
      const level = levels[d];
      const isRightNode = idx % 2 === 1;
      const siblingIdx = isRightNode ? idx - 1 : idx + 1;
      siblings.push(level[siblingIdx] ?? level[idx]);
      idx = Math.floor(idx / 2);
    }
    return { leaf: this.leaves[index], siblings, index };
  }
}

// ---------------------------------------------------------------------------
// In-process stand-in for the deployed contract's public ledger + prover.
// Every method here corresponds 1:1 to a circuit/ledger field in
// contract.compact, so swapping in the real SDK later is a drop-in change.
// ---------------------------------------------------------------------------

class AnonEchoSimulator {
  constructor() {
    this.memberTree = new MemberMerkleTree();
    this.membershipRoot = this.memberTree.root();
    this.usedNullifiers = new Set(); // hex-encoded nullifiers
    this.feedbacks = new Map(); // index -> text
    this.feedbackCount = 0;
  }

  /** Mirrors circuit registerMember(memberCommitment). Admin-only in prod. */
  registerMember(secretKeyBuf) {
    const commitment = commitmentOf(secretKeyBuf);
    const index = this.memberTree.insert(commitment);
    this.membershipRoot = this.memberTree.root();
    return index;
  }

  /**
   * Mirrors circuit submitFeedback(). Takes the caller's private witnesses
   * (secret key + feedback text), "proves" the circuit, and applies the
   * resulting public effects to the ledger — exactly what a proof server +
   * validated transaction would do on real Midnight.
   */
  submitFeedback({ secretKeyBuf, memberIndex, feedbackText }) {
    const proof = generateSubmitFeedbackProof({
      secretKeyBuf,
      memberIndex,
      feedbackText,
      memberTree: this.memberTree,
      membershipRoot: this.membershipRoot,
    });

    // --- everything below only ever touches PUBLIC values from `proof` ---
    if (proof.root.toString('hex') !== this.membershipRoot.toString('hex')) {
      throw new Error('credential is not a verified group member');
    }
    const nullifierHex = proof.nullifier.toString('hex');
    if (this.usedNullifiers.has(nullifierHex)) {
      throw new Error('this credential has already submitted feedback');
    }

    this.usedNullifiers.add(nullifierHex);
    const index = this.feedbackCount++;
    this.feedbacks.set(index, proof.feedbackText);

    return { index, nullifier: nullifierHex, txHash: proof.simulatedTxHash };
  }

  hasSubmitted(secretKeyBuf) {
    return this.usedNullifiers.has(nullifierOf(secretKeyBuf).toString('hex'));
  }

  listFeedback() {
    return [...this.feedbacks.entries()].map(([index, text]) => ({ index, text }));
  }
}

// ---------------------------------------------------------------------------
// "Proof generation" — the private-witness computation a real Midnight
// prover would run inside the ZK circuit for submitFeedback(). Only the
// fields under `return` are ever exposed outside this function; the secret
// key and raw Merkle path never leave it.
// ---------------------------------------------------------------------------

function generateSubmitFeedbackProof({ secretKeyBuf, memberIndex, feedbackText, memberTree, membershipRoot }) {
  const commitment = commitmentOf(secretKeyBuf);
  const path = memberTree.pathFor(memberIndex);

  if (path.leaf.toString('hex') !== commitment.toString('hex')) {
    throw new Error('credential does not match supplied Merkle path');
  }

  // Recompute the root from the path, exactly like the circuit's
  // `path.root() == membershipRoot` assertion.
  let acc = path.leaf;
  let idx = path.index;
  for (const sibling of path.siblings) {
    acc = idx % 2 === 1 ? sha256(sibling, acc) : sha256(acc, sibling);
    idx = Math.floor(idx / 2);
  }

  if (SIMULATE_ZK_LAYER) {
    // Stand-in for real proof bytes. A genuine build calls the Midnight
    // proof server here and gets back a succinct ZK proof instead.
    const simulatedTxHash = sha256(acc, Buffer.from(feedbackText)).toString('hex');
    return { root: acc, nullifier: nullifierOf(secretKeyBuf), feedbackText, simulatedTxHash };
  }

  throw new Error('Real proof-server path not wired up — see wireRealMidnightProviders()');
}

// ---------------------------------------------------------------------------
// REAL NETWORK WIRING (reference only — not executed in this demo).
//
// Once you've compiled contract.compact and stood up a proof server, the
// equivalent flow uses the actual Midnight JS SDK roughly like this:
//
//   const { deployContract, findDeployedContract } = require('@midnight-ntwrk/midnight-js-contracts');
//   const { NetworkId } = require('@midnight-ntwrk/midnight-js-network-id');
//   const AnonEchoContract = require('./managed/anonecho/contract/index.cjs');
//
//   async function wireRealMidnightProviders(walletProvider) {
//     const providers = {
//       privateStateProvider: myPrivateStateProvider,   // stores your secret key locally
//       publicDataProvider: myPublicDataProvider,       // reads ledger state
//       zkConfigProvider: myZkConfigProvider,            // circuit keys from compactc output
//       proofProvider: myProofServerClient,              // talks to the proof server
//       walletProvider,                                   // signs & submits transactions
//       midnightProvider: walletProvider,
//     };
//
//     const witnesses = {
//       credentialSecretKey: () => loadMySecretKeyBytes(),
//       credentialMerklePath: () => computeMyMerklePath(), // from indexed memberTree
//       feedbackText: () => Buffer.from(myFeedbackText, 'utf8'),
//     };
//
//     const contract = await findDeployedContract(providers, {
//       contractAddress: DEPLOYED_ANONECHO_ADDRESS,
//       contract: new AnonEchoContract.Contract(witnesses),
//     });
//
//     // This is the call that actually generates the ZK proof and submits it.
//     const tx = await contract.callTx.submitFeedback();
//     return tx.public.txHash;
//   }
//
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Demo run
// ---------------------------------------------------------------------------

function main() {
  const anonEcho = new AnonEchoSimulator();

  // Three group members get registered (this is the public commitment
  // only — their secret keys never touch the ledger).
  const alice = randomSecretKey();
  const bob = randomSecretKey();
  const carol = randomSecretKey();

  const aliceIndex = anonEcho.registerMember(alice);
  anonEcho.registerMember(bob);
  anonEcho.registerMember(carol);

  console.log('Membership root after registration:', anonEcho.membershipRoot.toString('hex'));

  // Alice anonymously submits feedback, proving membership without
  // revealing which of the three registered credentials is hers.
  const result = anonEcho.submitFeedback({
    secretKeyBuf: alice,
    memberIndex: aliceIndex,
    feedbackText: 'The onboarding flow could use clearer error messages.',
  });
  console.log('Feedback submitted:', result);

  // A second submission from the same credential is rejected by the
  // nullifier check — spam prevention without breaking anonymity.
  try {
    anonEcho.submitFeedback({
      secretKeyBuf: alice,
      memberIndex: aliceIndex,
      feedbackText: 'Trying to post twice...',
    });
  } catch (err) {
    console.log('Expected rejection on double submission:', err.message);
  }

  console.log('Public feedback board:', anonEcho.listFeedback());
}

if (require.main === module) {
  main();
}

module.exports = {
  AnonEchoSimulator,
  MemberMerkleTree,
  commitmentOf,
  nullifierOf,
};
