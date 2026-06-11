# GABPBX Changelog

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
