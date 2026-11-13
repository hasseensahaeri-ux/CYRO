/* CYRO Secure Communication Lab - protocol core (no DOM, works in browsers and Node 18+).
   Everything here is REAL cryptography from Web Crypto: ECDH P-256 key agreement, HKDF-SHA256,
   AES-256-GCM, ECDSA P-256 signatures. The attacker is a local object that only touches the bytes
   handed to it; nothing ever leaves this process. */
(function (root, factory) {
  var c = (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) ? globalThis.crypto
        : (typeof require === "function" ? require("crypto").webcrypto : null);
  var api = (c && c.subtle) ? factory(c) : { supported: false };
  if (typeof module === "object" && module.exports) module.exports = api; else root.CommCore = api;
})(this, function (crypto) {
  "use strict";
  var subtle = crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder();
  var FRESH_MS = 30000;

  var toHex = function (buf) { return Array.from(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, "0"); }).join(""); };
  var fromHex = function (h) { return new Uint8Array((h.match(/../g) || []).map(function (x) { return parseInt(x, 16); })); };
  var rand = function (n) { return crypto.getRandomValues(new Uint8Array(n)); };
  async function sha(bytes) { return toHex(await subtle.digest("SHA-256", bytes)); }

  // ---------- keys ----------
  async function newIdentity(name) {
    var kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    var pub = toHex(await subtle.exportKey("raw", kp.publicKey));
    return { name: name, priv: kp.privateKey, pub: pub, fp: (await sha(fromHex(pub))).slice(0, 16) };
  }
  async function sign(identity, bytes) { return toHex(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, identity.priv, bytes)); }
  async function verify(pubHex, sigHex, bytes) {
    try {
      var k = await subtle.importKey("raw", fromHex(pubHex), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      return await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, fromHex(sigHex), bytes);
    } catch (e) { return false; }
  }
  async function newEphemeral() {
    var kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    return { priv: kp.privateKey, pub: toHex(await subtle.exportKey("raw", kp.publicKey)) };
  }
  async function deriveSession(eph, peerPubHex) {
    var peer = await subtle.importKey("raw", fromHex(peerPubHex), { name: "ECDH", namedCurve: "P-256" }, false, []);
    var bits = await subtle.deriveBits({ name: "ECDH", public: peer }, eph.priv, 256);
    var hk = await subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    var key = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode("CYRO-comm-v1"), info: enc.encode("aes-256-gcm") },
                                     hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    return { key: key, id: (await sha(new Uint8Array(bits))).slice(0, 8) };
  }

  // ---------- configuration ----------
  var PRESETS = {
    none: { encryption: false, signature: false, authHandshake: false, antiReplay: false },
    encrypted: { encryption: true, signature: false, authHandshake: false, antiReplay: false },
    signed: { encryption: false, signature: true, authHandshake: false, antiReplay: false },
    full: { encryption: true, signature: true, authHandshake: true, antiReplay: true }
  };
  function level(cfg) {
    var n = ["encryption", "signature", "authHandshake", "antiReplay"].reduce(function (a, k) { return a + (cfg[k] ? 1 : 0); }, 0);
    return n === 0 ? "insecure" : n === 4 ? "protected" : "partial";
  }

  async function createWorld(cfg) {
    var sender = await newIdentity("sender"), receiver = await newIdentity("receiver"), attacker = await newIdentity("attacker");
    return { cfg: cfg, sender: sender, receiver: receiver, attacker: attacker,
             pinned: { sender: sender.pub, receiver: receiver.pub },     // identities each side learned out-of-band
             session: null, rx: { session: null, lastSeq: 0 }, seq: 0, atk: { sessions: null, captured: [] } };
  }

  // ---------- handshake (ECDH, optionally authenticated with identity signatures) ----------
  async function handshake(world, mitm) {
    var cfg = world.cfg, out = { established: false, reason: null, noKey: false, mitm: !!mitm, checks: {}, keyId: null };
    world.session = null; world.rx = { session: null, lastSeq: 0 }; world.atk.sessions = null; world.seq = 0;
    if (!cfg.encryption) { out.established = true; out.noKey = true; return out; }
    var es = await newEphemeral(), er = await newEphemeral();
    var hello = async function (id, eph, role) {
      return { role: role, pub: eph.pub, sig: cfg.authHandshake ? await sign(id, enc.encode("CYRO-HS|" + role + "|" + eph.pub)) : null };
    };
    var m1 = await hello(world.sender, es, "sender"), m2 = await hello(world.receiver, er, "receiver");
    var m1d = m1, m2d = m2, atk = null;                                  // what each side actually receives
    if (mitm) {
      atk = { s: await newEphemeral(), r: await newEphemeral() };         // attacker keys facing sender / receiver
      m1d = { role: "sender", pub: atk.r.pub, sig: m1.sig };              // signature cannot be recomputed
      m2d = { role: "receiver", pub: atk.s.pub, sig: m2.sig };
    }
    var okR = true, okS = true;
    if (cfg.authHandshake) {
      okR = !!m1d.sig && await verify(world.pinned.sender, m1d.sig, enc.encode("CYRO-HS|sender|" + m1d.pub));
      okS = !!m2d.sig && await verify(world.pinned.receiver, m2d.sig, enc.encode("CYRO-HS|receiver|" + m2d.pub));
      out.checks = { receiverVerifiedSender: okR, senderVerifiedReceiver: okS };
      if (!okR || !okS) { out.reason = "handshake_auth"; return out; }
    }
    world.session = await deriveSession(es, m2d.pub);
    world.rx.session = await deriveSession(er, m1d.pub);
    if (mitm) world.atk.sessions = { toSender: await deriveSession(atk.s, es.pub), toReceiver: await deriveSession(atk.r, er.pub) };
    out.established = true; out.keyId = world.session.id; out.receiverKeyId = world.rx.session.id;
    out.keysMatch = world.session.id === world.rx.session.id;
    return out;
  }

  // ---------- packets ----------
  var headerString = function (h) { return [h.v, h.seq, h.ts, h.from, h.to].join("|"); };
  var bodyString = function (b) { return [b.mode, b.iv || "", b.data].join("|"); };
  var signedBytes = function (p) { return enc.encode(headerString(p.h) + "#" + bodyString(p.body)); };

  async function buildPacket(world, text, now) {
    var h = { v: 1, seq: ++world.seq, ts: now, from: "sender", to: "receiver" }, body;
    if (world.cfg.encryption) {
      if (!world.session) throw new Error("no_session");
      var iv = rand(12);
      var ct = await subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: enc.encode(headerString(h)) }, world.session.key, enc.encode(text));
      body = { mode: "aesgcm", iv: toHex(iv), data: toHex(ct) };
    } else body = { mode: "plain", iv: "", data: toHex(enc.encode(text)) };
    var p = { h: h, body: body, sig: null };
    if (world.cfg.signature) p.sig = await sign(world.sender, signedBytes(p));
    return p;
  }

  // Receiver pipeline: authenticity -> integrity/decryption -> freshness.
  async function openPacket(world, p, now) {
    var cfg = world.cfg, rx = world.rx, checks = { signature: null, integrity: null, freshness: null }, reason = null, text = null;
    if (cfg.signature) {
      checks.signature = !!p.sig && await verify(world.pinned.sender, p.sig, signedBytes(p));
      if (!checks.signature) reason = "bad_signature";
    }
    if (!reason) {
      if (cfg.encryption) {
        if (p.body.mode !== "aesgcm" || !rx.session) { checks.integrity = false; reason = "integrity"; }      // downgrade attempt
        else {
          try {
            var pt = await subtle.decrypt({ name: "AES-GCM", iv: fromHex(p.body.iv), additionalData: enc.encode(headerString(p.h)) },
                                          rx.session.key, fromHex(p.body.data));
            text = dec.decode(pt); checks.integrity = true;
          } catch (e) { checks.integrity = false; reason = "integrity"; }
        }
      } else if (p.body.mode === "plain") text = dec.decode(fromHex(p.body.data));
      else { checks.integrity = false; reason = "integrity"; }
    }
    if (!reason && cfg.antiReplay) {
      checks.freshness = Math.abs(now - p.h.ts) <= FRESH_MS && p.h.seq > rx.lastSeq;
      if (!checks.freshness) reason = "replay";
    }
    var accepted = !reason;
    if (accepted && p.h.seq > rx.lastSeq) rx.lastSeq = p.h.seq;
    return { accepted: accepted, reason: reason, text: accepted ? text : null, checks: checks };
  }

  // ---------- attacker toolkit (acts only on the packet object it is handed) ----------
  var clone = function (p) { return JSON.parse(JSON.stringify(p)); };

  async function eavesdrop(world, p) {
    if (p.body.mode === "plain") { var t = dec.decode(fromHex(p.body.data)); return { readable: true, text: t, view: t, how: "plaintext" }; }
    var sessions = world.atk.sessions;
    if (sessions) {                                                      // MITM: the attacker owns a real session key with the sender
      try {
        var pt = await subtle.decrypt({ name: "AES-GCM", iv: fromHex(p.body.iv), additionalData: enc.encode(headerString(p.h)) },
                                      sessions.toSender.key, fromHex(p.body.data));
        return { readable: true, text: dec.decode(pt), view: p.body.data.slice(0, 48) + "…", how: "mitm_key" };
      } catch (e) { /* fall through */ }
    }
    var guess = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["decrypt"]);   // a real, failing decryption attempt
    try {
      await subtle.decrypt({ name: "AES-GCM", iv: fromHex(p.body.iv), additionalData: enc.encode(headerString(p.h)) }, guess, fromHex(p.body.data));
      return { readable: true, text: null, view: p.body.data.slice(0, 48) + "…", how: "lucky" };
    } catch (e) { return { readable: false, text: null, view: p.body.data.slice(0, 48) + "…", how: "ciphertext_only" }; }
  }

  function editText(t) { return /\d+/.test(t) ? t.replace(/\d+/, "9999") : t + " (edited by attacker)"; }

  function tamper(p) {
    var q = clone(p), change;
    if (q.body.mode === "plain") {
      var from = dec.decode(fromHex(q.body.data)), to = editText(from);
      q.body.data = toHex(enc.encode(to)); change = { kind: "text", from: from, to: to };
    } else {
      var b = fromHex(q.body.data); b[0] ^= 0x01; q.body.data = toHex(b); change = { kind: "bit", from: "bit 0 of byte 0", to: "flipped" };
    }
    return { packet: q, change: change };
  }

  function replay(p) { return clone(p); }

  async function forge(world, text, now) {
    var cfg = world.cfg, h = { v: 1, seq: world.seq + 1, ts: now, from: "sender", to: "receiver" }, body;
    if (cfg.encryption) {                                                // attacker has no session key: best effort with its own key
      var own = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]), iv = rand(12);
      var ct = await subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: enc.encode(headerString(h)) }, own, enc.encode(text));
      body = { mode: "aesgcm", iv: toHex(iv), data: toHex(ct) };
    } else body = { mode: "plain", iv: "", data: toHex(enc.encode(text)) };
    var p = { h: h, body: body, sig: null };
    if (cfg.signature) p.sig = await sign(world.attacker, signedBytes(p));    // signed with the attacker's OWN key
    return p;
  }

  // On-path relay after a successful key substitution: decrypt, optionally edit, re-encrypt for the receiver.
  async function mitmRelay(world, p, modify) {
    var read = await eavesdrop(world, p), q = clone(p);
    if (p.body.mode === "plain") {
      if (modify) { var to = editText(read.text); q.body.data = toHex(enc.encode(to)); }
      return { packet: q, read: read };
    }
    if (!read.readable || !world.atk.sessions) return { packet: q, read: read };
    var text = modify ? editText(read.text) : read.text, iv = rand(12);
    var ct = await subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: enc.encode(headerString(q.h)) }, world.atk.sessions.toReceiver.key, enc.encode(text));
    q.body = { mode: "aesgcm", iv: toHex(iv), data: toHex(ct) };
    return { packet: q, read: read };
  }

  return { supported: true, PRESETS: PRESETS, level: level, createWorld: createWorld, handshake: handshake, buildPacket: buildPacket,
           openPacket: openPacket, eavesdrop: eavesdrop, tamper: tamper, replay: replay, forge: forge, mitmRelay: mitmRelay,
           toHex: toHex, fromHex: fromHex, headerString: headerString, FRESH_MS: FRESH_MS };
});
