// Verifies the Secure Communication Lab protocol with REAL Web Crypto: every attack against every protection level.
// Run: node tests/comm_core.test.js   (Node 18+; optional developer test, the app itself needs only a browser)
const assert = require("assert");
const C = require("../frontend/static/js/comm-core.js");
const TEXT = "Transfer 100 to account 4521";
const P = C.PRESETS;

async function run(cfg, attack) {
  const w = await C.createWorld(cfg), now = Date.now();
  const hs = await C.handshake(w, attack === "mitm");
  if (!hs.established) return { aborted: true, reason: hs.reason };
  const pkt = await C.buildPacket(w, TEXT, now), out = { hs: hs };
  if (attack === "eavesdrop") { out.read = await C.eavesdrop(w, pkt); out.rx = await C.openPacket(w, pkt, now); }
  else if (attack === "tamper") { const t = C.tamper(pkt); out.rx = await C.openPacket(w, t.packet, now); out.change = t.change; }
  else if (attack === "replay") { out.first = await C.openPacket(w, pkt, now); out.rx = await C.openPacket(w, C.replay(pkt), now + 2000); }
  else if (attack === "impersonate") { out.rx = await C.openPacket(w, await C.forge(w, "Transfer 5000 to attacker", now), now); }
  else if (attack === "mitm") { const r = await C.mitmRelay(w, pkt, true); out.read = r.read; out.rx = await C.openPacket(w, r.packet, now); }
  else out.rx = await C.openPacket(w, pkt, now);
  return out;
}

const cases = [];
const t = (name, fn) => cases.push([name, fn]);

t("baseline: honest delivery works in every preset", async () => {
  for (const [name, cfg] of Object.entries(P)) {
    const r = await run(cfg, "none");
    assert.ok(r.rx.accepted && r.rx.text === TEXT, name);
  }
});
t("eavesdrop: readable only without encryption", async () => {
  assert.strictEqual((await run(P.none, "eavesdrop")).read.readable, true);
  assert.strictEqual((await run(P.signed, "eavesdrop")).read.readable, true);        // signatures give no secrecy
  for (const k of ["encrypted", "full"]) {
    const r = await run(P[k], "eavesdrop");
    assert.strictEqual(r.read.readable, false); assert.strictEqual(r.read.how, "ciphertext_only"); assert.ok(r.rx.accepted);
  }
});
t("tamper: accepted when unprotected, rejected otherwise (with the right reason)", async () => {
  const none = await run(P.none, "tamper"); assert.ok(none.rx.accepted && none.rx.text.includes("9999"));
  const enc = await run(P.encrypted, "tamper"); assert.deepStrictEqual([enc.rx.accepted, enc.rx.reason], [false, "integrity"]);
  const sig = await run(P.signed, "tamper"); assert.deepStrictEqual([sig.rx.accepted, sig.rx.reason], [false, "bad_signature"]);
  const full = await run(P.full, "tamper"); assert.deepStrictEqual([full.rx.accepted, full.rx.reason], [false, "bad_signature"]);
});
t("replay: only anti-replay stops it (encryption and signatures alone do not)", async () => {
  for (const k of ["none", "encrypted", "signed"]) { const r = await run(P[k], "replay"); assert.ok(r.first.accepted && r.rx.accepted, k); }
  const full = await run(P.full, "replay"); assert.ok(full.first.accepted); assert.deepStrictEqual([full.rx.accepted, full.rx.reason], [false, "replay"]);
});
t("replay: stale timestamp is rejected too", async () => {
  const w = await C.createWorld(P.full); await C.handshake(w, false);
  const p = await C.buildPacket(w, TEXT, Date.now() - 120000);
  assert.strictEqual((await C.openPacket(w, p, Date.now())).reason, "replay");
});
t("impersonation: accepted only with no protection", async () => {
  assert.ok((await run(P.none, "impersonate")).rx.accepted);
  assert.strictEqual((await run(P.encrypted, "impersonate")).rx.reason, "integrity");
  assert.strictEqual((await run(P.signed, "impersonate")).rx.reason, "bad_signature");
  assert.strictEqual((await run(P.full, "impersonate")).rx.reason, "bad_signature");
});
t("MITM: encryption alone is read AND modified; signatures block the edit; authenticated handshake aborts it", async () => {
  const none = await run(P.none, "mitm"); assert.ok(none.read.readable && none.rx.accepted && none.rx.text.includes("9999"));
  const enc = await run(P.encrypted, "mitm");
  assert.ok(enc.hs.mitm && enc.read.readable && enc.read.how === "mitm_key"); assert.ok(enc.rx.accepted && enc.rx.text.includes("9999"));
  const encSig = await run({ encryption: true, signature: true, authHandshake: false, antiReplay: false }, "mitm");
  assert.ok(encSig.read.readable); assert.deepStrictEqual([encSig.rx.accepted, encSig.rx.reason], [false, "bad_signature"]);
  const full = await run(P.full, "mitm"); assert.deepStrictEqual([full.aborted, full.reason], [true, "handshake_auth"]);
});
t("honest sessions derive the same key on both sides", async () => {
  const w = await C.createWorld(P.full); const hs = await C.handshake(w, false);
  assert.ok(hs.established && hs.keysMatch && hs.keyId.length === 8);
});
t("security level", async () => {
  assert.deepStrictEqual([C.level(P.none), C.level(P.encrypted), C.level(P.full)], ["insecure", "partial", "protected"]);
});

(async () => {
  let failed = 0;
  for (const [name, fn] of cases) {
    try { await fn(); console.log("ok   -", name); } catch (e) { failed++; console.log("FAIL -", name, "\n      ", e.message); }
  }
  console.log(failed ? `${failed} failed` : `all ${cases.length} passed`);
  process.exit(failed ? 1 : 0);
})();
