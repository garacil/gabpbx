# GABPBX Changelog

## Unreleased

_No changes yet._

## 1.1

`chan_sofia` matures into a more capable SIP driver, building on the 1.0 correctness
base: a modular source layout, new SIP capabilities, and continued performance,
forwarding and reliability work.

### Modular source layout

- **The driver is now a core plus cohesive subsystem modules.** `channels/chan_sofia.c`
  keeps the channel technology vtable, event dispatch, authentication, and the call /
  register / configuration core; the subsystems that form clean functional boundaries
  move into `channels/sofia/`: `sofia_sdp.c` (SDP offer/answer), `sofia_t38.c` (T.38
  fax), `sofia_presence.c` (presence/BLF), `sofia_publish.c` (outbound PUBLISH),
  `sofia_ami.c` (AMI actions), `sofia_cli.c` (CLI commands) and `sofia_blacklist.c`,
  alongside the existing `sdp_crypto.c` / `srtp.c`. It is still one loadable module
  (`chan_sofia.so`), the core is ~44% smaller, and the change is **behavior-identical** —
  every extraction was wire-validated and lock-checked.

### New SIP capabilities

- **Presence / BLF.** Inbound `SUBSCRIBE` → `NOTIFY` for `dialog-info+xml`, `pidf+xml`
  and `xpidf+xml`, so busy-lamp-field and presence watchers light up. Governed by the
  existing `allowsubscribe` / `subscribecontext` gates.
- **Outbound PUBLISH (RFC 3903).** Publishes local extension/dialog state to a central
  state server (`publish_server`, with reload reconciliation and `sip show publications`).
- **Outbound REGISTER authentication.** chan_sofia now answers a `401`/`407` challenge
  when registering to an upstream trunk.
- **Connection keepalive.** `tcp_keepalive` / `tcp_pingpong` keep TCP/TLS connections to
  carriers and NAT'd endpoints alive.
- **Instance advertisement on outbound REGISTER** (`gruu`) — adds `+sip.instance` to the
  outbound Contact.
- **TLS hardening** (`tlsverify`, default off) — peer-certificate verification policy for
  TLS transports.
- **Digest algorithm offer** (`auth_algorithms = both | md5 | sha256`) — controls which
  algorithm the `WWW-Authenticate` challenge offers, with anti-downgrade enforcement.
- **CLI additions:** `sip show registry`, `sip unregister`, `sip show publications`, plus
  peer-name tab completion on `sip show peer`.

### Performance & scaling

- **Bounded REGISTER offload pool** (`register_pool`, default **OFF**). Offloads the
  realtime-database writes for REGISTER to a small fixed pool of AOR-keyed worker
  lanes, so a slow-database REGISTER storm no longer head-of-line-blocks
  INVITE/OPTIONS on the single signaling thread. Bounded (fixed lanes + in-flight
  cap), reversible at runtime with `sofia reload`, and byte-for-byte the legacy
  inline path until enabled. Same separation Kamailio gets from its async
  usrloc/worker model and FreeSWITCH from its thread pools.
- **Carrier-scale hash sizing.** Peer and dialog hash bucket caps enlarged
  (`MAX_PEER_BUCKETS` 16381 → 65521, `MAX_DIALOG_BUCKETS` 8191 → 32749) so O(1)
  peer/dialog lookups keep a load factor below 1 into tens of thousands of peers
  and high concurrent-dialog volume.

### Call forwarding

- **`forceddiversion`** (per-peer). Forces a trunk-owned DID as the diverting party
  in the outbound `Diversion` header (RFC 5806) on forwarded calls, so a carrier can
  validate the diversion against a number it provisions for the trunk. Emitted only
  when the channel carries a redirect marker; empty (default) keeps the legacy
  data-driven behavior.

### Reliability

- **Continued concurrency and memory-safety hardening** across the registration, media,
  presence and teardown paths, extending the 1.0 correctness work. A re-INVITE that is
  rejected now leaves the live call fully unchanged (validate-then-commit SDP handling);
  REGISTER side effects run outside the peer lock; and the SUBSCRIBE/NOTIFY, fork and
  qualify paths were swept for use-after-free and lock-order issues — each fix verified
  under a thread-debug build with `core show locks`.

## 1.0

The first tagged GABPBX release. `chan_sofia` — the Sofia-SIP based `chan_sip`
replacement — reaches a stable, production-ready baseline.

### Why this release matters

`chan_sofia` lets you move off the aging `chan_sip` without rewriting your
deployment. It keeps the public compatibility surface that existing systems
depend on:

- Channel technology `SIP` (so `Dial(SIP/peer)` is unchanged).
- CLI: `sip show peers`, `sip show peer`, `sip show channels`, `sip set debug`.
- AMI: `SIPpeers`, `SIPshowpeer`, `SIPqualifypeer`, `SIPshowregistry`, `SIPnotify`.
- Realtime family `sippeers`.
- Dialplan functions `SIPPEER`, `SIPCHANINFO`, `SIP_HEADER`, `CHECKSIPDOMAIN`.

For most systems the switch is a single change in `modules.conf`:

```ini
noload => chan_sip.so
load   => chan_sofia.so
```

### What chan_sofia gives you

Registration, digest authentication (MD5 and SHA-256), inbound and outbound
calls, re-INVITE / hold, attended and blind transfer, multi-contact forking,
RTP with NAT handling, SRTP, session timers, MWI, T.38 fax, UDP / TCP / TLS
transports, per-peer permit/deny ACLs and call limits, and PostgreSQL realtime
peers — all on the maintained Sofia-SIP NUA stack.

### The 1.0 focus: concurrency and memory safety

1.0 is a deep correctness pass that makes the driver dependable under real
traffic and routine operations:

- **One authoritative locking model.** A single block at the top of
  `channels/chan_sofia.c` defines the rule the whole driver follows: one SIP
  event-loop thread owns the mutable peer and dialog state; every other thread
  (dialplan, CLI, AMI, bridge, scheduler, registration and qualify) reads it
  under the `channel -> pvt -> peer` lock order. Every inline lock note in the
  file is an instance of that model.
- **Dialog teardown races closed.** Every in-dialog request and response that
  touches a dialog is revalidated and reference-counted for the life of its
  handler, so a concurrent hangup can no longer free the dialog underneath it.
- **`sip reload` is safe under load.** Peer string fields, and the global
  localnet and contact ACL lists, are read under locks, so a reload that frees
  and rebuilds them is never observed half-built by a thread that is setting up
  or running a call.
- **Lock-order and lifetime fixes.** The T.38 reINVITE-timeout path no longer
  inverts the channel and dialog locks; transfer, fork-winner and
  bridged-channel paths no longer leak a reference or a SIP handle; AMI and
  hangup paths snapshot owner-derived data under the dialog lock.
- **Exercised, not just reasoned about.** A repeatable stress procedure — a SIP
  call flood plus a `sip reload` loop, run together under a thread-debug
  (`DEBUG_THREADS`) build so locks can be inspected with `core show locks` —
  drives these paths. The 1.0 set passed with no crash, deadlock or memory
  error.

See the [chan_sofia wiki page](https://github.com/garacil/gabpbx/wiki/Chan-Sofia)
for the full concurrency model, configuration reference and operational recipes.
