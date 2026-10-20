// banner.test.ts: run with `npm test` (plain node type stripping, no test framework).
import assert from "node:assert/strict";
import { GREEN, HOLD_MS, applyEvent, expire, fromSnapshot, summarize } from "./banner.ts";

const block = { type: "BLOCK", tgid: 4422, comm: "curl", file: "/p/.env", hook: "connect",
  family: "ipv4", daddr: "192.168.122.1", dport: 9999, parent_tgid: null, mode: "enforce" };
const allow = { ...block, type: "ALLOW", daddr: "127.0.0.1", dport: 8080 };
const tag = { type: "TAG", tgid: 4421, comm: "python3", file: "/p/.env", hook: "file_open",
  family: null, daddr: null, dport: null, parent_tgid: null, mode: "enforce" };

// BLOCK: red for 5 s, other events don't cut the hold short, then green.
let b = applyEvent(GREEN, block, 1000);
assert.equal(b.level, "red");
b = applyEvent(b, allow, 2000);
assert.equal(b.level, "red");
assert.equal(expire(b, 1000 + HOLD_MS - 1).level, "red");
assert.equal(expire(b, 1000 + HOLD_MS), GREEN);

// WOULD_BLOCK: amber, but never overrides a live red hold.
assert.equal(applyEvent(GREEN, { ...block, type: "WOULD_BLOCK" }, 0).level, "amber");
assert.equal(applyEvent(applyEvent(GREEN, block, 0), { ...block, type: "WOULD_BLOCK" }, 10).level, "red");

// ERROR: red and sticky; no timer clears it, the next event does.
let e = applyEvent(GREEN, { type: "ERROR", message: "BPF load failed" }, 0);
assert.equal(e.level, "red");
assert.equal(expire(e, 10 * HOLD_MS).level, "red");
assert.equal(applyEvent(e, tag, 1).level, "green");
assert.equal(applyEvent(e, block, 1).title, "BLOCKED");

// SNAPSHOT replays only a trailing ERROR, never an old BLOCK hold.
assert.equal(fromSnapshot([tag, block]), GREEN);
assert.equal(fromSnapshot([tag, { type: "ERROR", message: "x" }]).sticky, true);
assert.equal(fromSnapshot([]), GREEN);

// Text omits null fields: a TAG has no address.
assert.equal(summarize(tag), "python3 pid 4421  ·  read /p/.env  ·  via file_open");
assert.ok(!summarize(tag).includes("null"));
assert.equal(summarize(block), "curl pid 4422  ·  → 192.168.122.1:9999  ·  read /p/.env  ·  via connect");
assert.equal(summarize({ type: "BLOCK", family: "ipv6", daddr: "2001:db8::1", dport: 53 }), "→ [2001:db8::1]:53");
assert.equal(summarize({ type: "READY", mode: "audit", protect: ["/p/.env"], allow: [] }),
  "protect /p/.env  ·  allow (none)  ·  mode audit");

console.log("banner tests: ok");
