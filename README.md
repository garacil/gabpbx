# GABPBX

GABPBX is the Germán Aracil Boned PBX: a GPLv2 open-source PBX and telephony toolkit maintained by Germán Luis Aracil Boned <garacilb@gmail.com>.

---

## The basics — a fork of Asterisk

GABPBX is a **fork of Asterisk**, first created in **2008**. It keeps everything that made Asterisk dependable, and concentrates its new engineering where it matters most — the SIP channel.

| You keep | What it means |
| :-- | :-- |
| **The proven Asterisk architecture** | Modules, channels, the PBX core, the scheduler — unchanged. |
| **The same dialplan** | Contexts, extensions, priorities, applications and functions, byte-for-byte familiar. |
| **The same AMI** | The Asterisk Manager Interface and its event/action model. |
| **The same realtime APIs** | `extconfig.conf`, the realtime engines, and the familiar `sippeers` / `sipregs` families. |

Existing Asterisk, Digium and third-party copyright notices and the GPLv2 terms are preserved in the source files where they apply.

---

## GABPBX 1.4.0 — the star is `chan_sofia`

**`chan_sofia` is a complete, modern SIP channel driver built on the battle-tested [Sofia-SIP](https://github.com/garacil/sofia-sip) NUA stack — a true drop-in replacement for the aging `chan_sip`, with every `chan_sip` capability and a great deal more.** It is **feature-complete** and **security-hardened** — with **two-way WebRTC video** and **browser-to-browser DataChannels**. Release **1.3** makes the core **faster at scale**: the string hash that powers every internal hash table is now **XXH3-64**, the `chan_sofia` lookup tables are retuned for carrier load, and a new **`core test hash`** command lets you measure hash throughput on your own hardware. Release **1.3.1** selects the outbound media profile by each target's real transport (a WebRTC browser over wss gets DTLS-SRTP; a plain udp/tls phone gets RTP/AVP), so one account can be used from several phones of different technologies at once; **routes outbound calls to a NAT'd peer back to its learned public source** (a registered PBX or phone behind NAT now actually rings, instead of the INVITE being sent to an unreachable private address); and adds a configurable local-blacklist ban window (`blacklist_ban`, in minutes). Release **1.3.5** makes **inbound calls to a browser endpoint** (where GABPBX is the SDP offerer) connect with **two-way audio**: it repairs the ICE role conflict — a browser answering the offer would default to the controlled role, leaving both ends controlled and nobody nominating, so GABPBX now replies `487 Role Conflict` (RFC 8445 §7.3.1.1) to flip the browser to controlling — and it defers the DTLS handshake until the answer's `a=fingerprint` arrives, so an early `ClientHello` no longer fails the call. It also ships a `sip set debug sdp` SDP/ICE tracer and tags every SIP debug line with its `[from|to|callid]` transaction identity. Release **1.4.0** brings the WebRTC media path to a reliable baseline: audio latches immediately on every integrity-authenticated ICE check (removing the intermittent one-way / delayed audio and the offerer-inbound deaf case), video is negotiated over a single bundled ICE/DTLS transport (`a=group:BUNDLE`, RFC 8843; opt-in `webrtc_video_bundle`), DTMF reaches full `chan_sip` parity, the registrar implements per-Contact REGISTER bindings (RFC 3261 §10.3), TLS accepts 1.2 by default, and — since ws/wss/tls SIP is encrypted on the wire — GABPBX can **stream every SIP message decrypted** to a Homer/**HEP** collector or a plain-text file (`sip_capture_address` / `sip_capture_file`, or the runtime `sip set debug capture` / `file`), alongside default-off `rtp set debug ice` and `sip set debug fork` tracers that open a window into the WebRTC media and call-fork lifecycle.

Where `chan_sip` hand-rolled its own parser, `chan_sofia` rides a real SIP transaction state machine — the same library lineage that powers large-scale softswitches — and puts the PBX behavior on top. The result is a SIP driver that is at once **more capable, more secure, and dramatically more scalable** than the channel it replaces.

### Drop-in migration in two lines

```ini
; /etc/gabpbx/modules.conf
noload => chan_sip.so
load   => chan_sofia.so
```

Your dial plans, your `sip show …` muscle memory, your `SIPpeers` / `SIPshowpeer` AMI integrations, the `sippeers` realtime family and the `SIPPEER` / `SIP_HEADER` dialplan functions **all keep working**. The channel tech is still `SIP`, so every `${CHANNEL(...)}`, CDR, AMI and dialplan consumer sees `SIP/<peer>` exactly as before. (`chan_sofia` and `chan_sip` register the same public names — load one or the other per instance, not both.)

### At a glance

- **Drop-in for `chan_sip`** — same `SIP/<peer>` channel, same `sip show …` CLI, same `SIPpeers` AMI, same `sippeers` realtime family.
- **Far beyond `chan_sip`** — SIP Outbound, Path, Service-Route, GRUU, PRACK/100rel, UPDATE, REFER transfer, MESSAGE, PUBLISH, presence/BLF, SHA-256 auth, and more.
- **WebRTC ready** — browsers register and call over secure WebSocket with DTLS-SRTP, ICE-lite, rtcp-mux and BUNDLE, **two-way audio, two-way video and relayed DataChannels**, with **no `pjproject` and no `libnice`** in the tree.
- **Built for carrier scale** — a single Sofia event thread plus a small fixed I/O pool, **O(1) hash tables with fast XXH3-64 hashing**, a bounded register pool under storms, and a lean high-throughput media engine.
- **Exceptionally robust** — hardened through a rigorous, multi-round adversarial correctness, concurrency and security review.

---

## `chan_sofia` — the complete feature catalogue

Every capability is enumerated below, grouped for scanning. Each is real and lives in `channels/chan_sofia.c`, `channels/sofia/*.c`, or `res/res_rtp_gabpbx.c`.

### 1. SIP signaling

| Feature | What it does |
| :-- | :-- |
| **Inbound REGISTER / registrar** | Phones register their location with credential checks, per-peer source ACLs and unknown-peer rejection. |
| **REGISTER expiry bounds** | Enforces min/max registration lifetimes; a too-short refresh gets `423 Interval Too Brief` with `Min-Expires`, blunting registration-flood abuse. |
| **Per-Contact REGISTER bindings (RFC 3261 §10.3)** | Each Contact in a REGISTER binds, refreshes and de-registers **independently** under lock, honouring its own `;expires` (a per-binding `expires=0` removes just that binding), and the `200 OK` returns each binding's own remaining expiry. A Contact-less REGISTER is answered as a pure "where am I registered?" query without changing state. |
| **Expiry-aware state + all-expired no-route guard** | `sip show peer <name> detail` reports each binding's live state (AVAILABLE / EXPIRED / IN-CALL); a call to a peer whose bindings have **all expired** returns `CHANUNAVAIL` instead of routing to a stale binding. |
| **Connection-flow close (RFC 5626)** | A connection-oriented binding (WSS / WS / TLS / TCP) is dropped promptly when its underlying connection closes, instead of lingering until the registration expires — so a WebSocket browser that reconnects on a page refresh never leaves a stale binding. `flowclose_emit_unregister` (default `no`) chooses whether the external unregister side-effects — AMI `PeerStatus`, BLF / hint device-state and regexten cleanup — fire on a flow close; the binding and routing state are always corrected regardless. |
| **Outbound REGISTER (trunk)** | `register =>` lines register the PBX to upstream providers, with scheduled re-registration and an AMI `Registry` event on the response. |
| **Qualify / OPTIONS keepalive** | Periodic SIP OPTIONS pings confirm reachability, measure round-trip time, and mark dead peers unreachable. |
| **RTP keepalive** | Optional tiny periodic media packets keep NAT/firewall pinholes open during a call or on hold. |
| **INVITE handling (in + out)** | The call-setup engine: incoming calls into the dialplan, outgoing calls to peers and trunks, plus re-INVITE. |
| **INVITE digest authentication** | Incoming calls can be challenged for a password, with toll-fraud guards for unknown and guest callers (`alwaysauthreject`, `allowguest=no`). |
| **Digest algorithms — MD5 + SHA-256 (RFC 7616)** | Selectable per deployment, with anti-downgrade so the server accepts only an algorithm it offered. |
| **Cryptographic nonce + TTL/stale** | Each challenge uses a fresh 128-bit nonce from `/dev/urandom` with a configurable lifetime; an expired-nonce client is re-challenged (`stale`), not rejected. |
| **WWW-Authenticate per policy** | Advertises exactly the algorithms the operator enabled (MD5 first for legacy phones, SHA-256, or both). |
| **100rel / PRACK (RFC 3262)** | Reliable provisional responses, so call-progress like "ringing" is acknowledged and never lost on a lossy link. |
| **UPDATE (RFC 3311)** | In-dialog media renegotiation — hold, codec swap, session-timer refresh — without disrupting the dialog. |
| **Session timers (RFC 4028)** | Long calls are periodically refreshed so a crashed phone or dropped link cannot leave a zombie call billing forever. |
| **Q.850 cause / Reason (RFC 3326)** | Internal hangup reasons map to standardized telephony cause codes on outbound BYE/CANCEL and parse back inbound. |
| **REFER transfer — outbound** | Transfers a connected call to a third party, blind or attended (with `Replaces`), via a tech callback and a `SofiaTransfer()` application. |
| **REFER transfer — inbound** | Honors a phone's REFER, including attended transfers via `Replaces` and the RFC 5589 transferer-leg BYE deferral. |
| **Out-of-dialog MESSAGE / SIP SIMPLE** | Sends and receives SIP instant messages independent of a call; inbound routes to a `message_context`, outbound from the dialplan or AMI. |
| **Inbound SUBSCRIBE/NOTIFY routing** | Routes each event-package subscription to the right handler (MWI, dialog-info, presence), rejecting unsupported packages with `489 Bad Event`. |
| **Presence + BLF / dialog-info** | Drives speed-dial lamps showing whether a monitored colleague is idle, ringing or on a call, in `dialog-info+xml`, `pidf+xml` or `xpidf+xml`. |
| **MWI — inbound subscription + NOTIFY (RFC 3842)** | Lights message-waiting indicators with the voicemail count, solicited or unsolicited. |
| **MWI — outbound SUBSCRIBE watcher** | Subscribes to a provider's voicemail-status notifications and re-lights local phones, with retry/backoff on a failed initial subscribe. |
| **Generic outbound SUBSCRIBE (RFC 6665)** | Subscribes a trunk to any event package and surfaces each notification as a `SofiaEventNotify` AMI event. |
| **Outbound PUBLISH / EPA (RFC 3903)** | Publishes a local extension's presence/state upstream, refreshing with `SIP-If-Match`/ETag. |
| **INFO — DTMF relay** | Carries key-press digits inside SIP signaling both ways, separate from inband or RFC 2833. |
| **OPTIONS — capability responder** | Answers SIP OPTIONS pings with a 200 OK advertising every supported method plus `Accept: application/sdp`. |
| **GRUU (RFC 5627/5626)** | Advertises a stable per-device instance ID and learns the routable address the registrar mints. |
| **Path (RFC 3327)** | As a registrar, records and honors the edge-proxy route a phone registered through, rejecting forged Path with `420 Bad Extension`. |
| **Service-Route (RFC 3608)** | On outbound registration, remembers the provider-mandated route and pre-loads it on outgoing calls. |
| **SIP Outbound / reg-id + Flow-Timer (RFC 5626)** | Advertises outbound support and a registration ID and honors the provider's flow-keepalive timer, for reliable connectivity behind firewalls. |
| **Diversion (RFC 5806)** | Carries forwarding history outbound and parses it inbound into redirecting info, with a per-trunk forced-Diversion override. |
| **SIP history / call-event recording** | A per-call timeline of every SIP request and response for diagnostics, viewable while a call is traced. |
| **Local anti-abuse SIP blacklist** | Counts and bans abusive source IPs (failed-auth probes, malformed requests, unknown-peer REGISTERs) to blunt brute-force and scanning. |

### 2. Media & WebRTC

| Feature | What it does |
| :-- | :-- |
| **RTP/RTCP media stack (forked engine)** | RFC 3550 RTP/RTCP with symmetric-RTP NAT traversal, jitter handling, RED and sender/receiver reports. One forked engine (`gabpbx_rtp_engine`) carries plain calls and WebRTC alike. |
| **SRTP with SDES (RFC 4568)** | Encrypted media via SDP `a=crypto` — AES-CM 128/192/256 with HMAC-SHA1 80/32 and two GCM suites — validated and staged so a bad `a=crypto` never silently downgrades a live call to plaintext. |
| **DTLS-SRTP keying (RFC 5763/5764)** | WebRTC-grade keying derived from a DTLS handshake over the media path, with SHA-256 fingerprints, ephemeral self-signed certs, and `a=setup` role negotiation. A fingerprint mismatch fails the call closed. |
| **WebRTC ICE-lite STUN responder (RFC 8445)** | A dependency-free ICE-lite agent — no `pjproject`, no `libnice`. GABPBX is permanently the controlled lite agent; it answers STUN checks, learns the peer, and latches the media path immediately on **every integrity-authenticated connectivity check** (RFC 8445 §7.3.1 / RFC 7675) — not only on the nominated USE-CANDIDATE pair — so a later-nominated pair can no longer leave a leg with intermittent one-way or delayed audio. When GABPBX is the SDP offerer, a browser that answers can wrongly keep the controlled role (both ends controlled → nobody nominates); GABPBX repairs this with a `487 Role Conflict` (RFC 8445 §7.3.1.1) that flips the browser to controlling, and it defers DTLS until the answer's fingerprint is installed so an early `ClientHello` cannot fail the call. |
| **RTCP multiplexing (RFC 5761)** | `rtcp-mux` so RTP and RTCP share one socket on WebRTC legs, with exactly one DTLS association per media stream. |
| **BUNDLE negotiation (RFC 8843)** | Emits session-level `a=group:BUNDLE` and per-m-line `a=mid`; unsupported offered m-lines are reflected back as port-0 rejections rather than 488-ing the session. |
| **SIP over secure WebSocket (WSS / RFC 7118)** | Browsers register and call over SIP-over-WSS (and plain WS); in-dialog ACK/BYE route back over the exact accepted WebSocket connection. |
| **WebRTC audio (browser-to-browser)** | A real two-way audio call between two WSS browsers, opt-in per peer with `webrtc=yes`. A `webrtc=yes` peer fails the call rather than fall back to insecure media. |
| **Two-way WebRTC video (VP8/H.264)** | GABPBX both accepts a browser's offered video and offers video itself. By default video runs on its own transport (separate mid, port and DTLS association from audio); the opt-in **`webrtc_video_bundle`** (per-peer or `[general]`, default off, requires `webrtc=yes`) instead carries audio and video over a **single bundled ICE/DTLS transport** per RFC 8843 max-bundle — payload-type-demultiplexed and tagged with the RTP MID header extension (RFC 8285) — for browsers that require max-bundle. |
| **WebRTC DataChannel relay (RFC 8831/8832/8841)** | Bridges WebRTC DataChannels back-to-back between two WebRTC legs — SCTP-over-DTLS bundled on the audio, a DCEP `OPEN`/`ACK` proxy and a PPID-preserving message relay. GABPBX both accepts an offered DataChannel and offers one to the bridged leg, so a `createDataChannel` between two browsers crosses end to end. Opt-in with `datachannel=yes` (needs a `usrsctp` build). |
| **Opus with passthrough-correctness fixes** | Opus (RFC 7587, 48 kHz, stereo, `useinbandfec`) is offered and answered, and a both-Opus call relays with no transcoding (codec selection, 48 kHz clocking, and a smoother exemption for Opus's variable-size frames). |
| **T.38 fax (UDPTL) with state machine** | Real-time T.38 over UDPTL with a 4-state negotiation machine, re-INVITE handling, `far-max-IFP` and a 5-second abort timeout; correctly suppressed inside WebRTC SDP. |
| **Direct media (re-INVITE bridging) with safety gates** | `directmedia` (alias `canreinvite`) lets endpoints exchange RTP directly when safe; any SRTP/DTLS leg, NAT'd peer or ACL mismatch forces local relay. |
| **Codec negotiation (offer/answer)** | Codecs emitted in preference order, answer intersected with local capability, no-common-audio offer cleanly rejected with `488`; `preferred_codec_only` narrows to one codec; per-codec fmtp for G.729, Opus and iLBC. |
| **DTMF: RFC 2833, SIP INFO, inband, auto** | All standard modes per peer, with a clash-safe telephone-event payload type, `relaxdtmf` for poor lines, and `SIPDtmfMode` to switch mode mid-call. |
| **RFC 7983 packet demux** | On a WebRTC leg, demuxes STUN, DTLS and (S)RTP/RTCP by first byte on the one muxed socket — dormant unless DTLS is active, so plain calls are untouched. |

### 3. Transports

| Feature | What it does |
| :-- | :-- |
| **Multi-transport listener** | One `nua_create()` spins up UDP, TCP, TLS, WS and WSS, each enabled only when its bind port is non-zero. |
| **Per-transport bind addresses/ports** | `bindaddr`/`bindport`, `tlsbindaddr`/`tlsbindport`, `wsbindaddr`/`wsbindport`, `wssbindaddr`/`wssbindport`, IPv6-aware per RFC 3261 §19.1.2. |
| **TLS hardening** | `tlsverify`, `tlsverifyclient` (mutual TLS), `tls_min_version`, `tls_ciphers`, `tls_verify_depth`, and verify-date — closing the accept-any-cert MITM hole sofia-sip leaves open by default. |
| **WSS certificate auto-aliasing** | Auto-creates the WSS-named cert/ca-bundle files the WebSocket transport expects from the standard `agent.pem`/`cafile.pem`. |
| **Placeholder-Contact routing** | A browser's Contact host is a placeholder, so requests route over the live accepted WebSocket with `;transport=wss` appended. |

### 4. Operations & `chan_sip` parity

| Feature | What it does |
| :-- | :-- |
| **CLI — `sip show …`** | `sip show peers`, `sip show peer <name>` (a concise, friendly summary — registration, endpoint, context, media, calls, qualify — followed by the per-contact list; `sip show peer <name> detail` for the full per-field dump, tab-completed), `sip show settings`, `sip show registry`, `sip show channels` / `channelstats`, `sip show inuse` — chan_sip's column layout, snapshotted under lock. |
| **CLI operations** | `sip reload`, `sip set debug [on\|off\|peer\|ip\|sdp]` (the `sdp` toggle dumps the generated offer SDP, the WebRTC offer-gate decision and the incoming answer — the signaling of WSS/TLS sessions already decrypted, which a packet capture cannot show; and every `Sofia: …` debug line is tagged with its `[from\|to\|callid]` SIP transaction identity), `sip qualify peer`, `sip unregister`, `sip prune realtime`, `sip notify`, plus the history and blacklist families. |
| **Decrypted SIP capture (HEP / file)** | `sip_capture_address` streams every SIP message — udp/tcp/tls/ws/wss, SDP included — **decrypted**, as HEP to a Homer / sipcapture collector (read it with `sngrep -H udp:HOST:PORT`); `sip_capture_file` writes the same stream to a plain-text file; either can be toggled at runtime with `sip set debug capture <host:port>` / `sip set debug file <path>`. Default-off `rtp set debug ice` and `sip set debug fork` tracers open a window into the WebRTC ICE/media path and the call-fork lifecycle. |
| **AMI parity** | `SIPpeers`/`SIPshowpeer`, `SIPqualifypeer`, `SIPshowregistry`, `SIPnotify`, and `SofiaMessageSend`, each mirroring chan_sip's field set (Transport extended to `ws`/`wss`). |
| **Realtime `sippeers` family** | On a cache miss a peer is loaded from `sippeers`, with optional dual-load of `sipregs` auto-detected via `ast_check_realtime`. |
| **Realtime registration write-back** | For realtime peers with `rtupdate=yes`, bindings are written back on REGISTER and cleared on unregister, with an optional bounded background pool. |
| **Dialplan functions** | `${SIPPEER()}`, `${SIP_HEADER()}`, `${SIPCHANINFO()}`, `${CHECKSIPDOMAIN()}` — chan_sip-parity verbatim. |
| **Per-peer option parity** | The full chan_sip per-peer vocabulary (`host`/`context`/`secret`/`transport`/`allow`/`disallow`/`nat`/`directmedia`/`qualify`/`callgroup`/`mohinterpret`/session timers/`insecure`/`permit`/`deny` and more) loads unchanged. |
| **NAT, ACL, MOH, qualify** | `nat=force_rport,comedia`; three independent ACL chains (source, contact, direct-media) plus a global `localha`; per-peer MOH; qualify with RTT and `PeerStatus` AMI transitions. |

### 5. Security & Robustness

| Feature | What it does |
| :-- | :-- |
| **MD5 + SHA-256 digest auth (RFC 7616)** | Per-deployment algorithm selection with anti-downgrade. |
| **Crypto-secure nonces + TTL/stale** | Fresh 128-bit `/dev/urandom` nonces; expired-nonce clients re-challenged, not rejected. |
| **Constant-time digest compare** | Response compared with a constant-time `memcmp` to deny a timing oracle. |
| **Fail-closed challenges** | `alwaysauthreject` makes an unknown peer indistinguishable from a bad password; `allowguest=no` returns 403; `force_invite_auth` overrides `insecure=invite` and raises an auditable AMI event. |
| **Three independent ACL chains** | Source, Contact, and direct-media ACLs, plus a global `localha`, with a timing-equalized 403 so ACL denial is not a peer-existence oracle. |
| **Multi-Contact REGISTER preflight** | A multi-Contact REGISTER is validated in full before any binding is applied. |
| **Local anti-abuse SIP blacklist** | Counts and bans abusive source IPs. |
| **REGISTER expiry bounds** | Enforced min/max lifetimes to blunt registration-flood abuse. |
| **TLS / WSS hardening** | Mutual TLS, min-version, ciphers, verify-depth/date on the TLS listener; WSS builds its own SSL context. |
| **SRTP validated, staged & deferred** | `a=crypto` validated in full and committed only past every reject gate; live keying withheld until the single commit block. |
| **DTLS-SRTP trust anchored on the fingerprint** | Fail-closed `X509_digest` + `memcmp` against the SDP `a=fingerprint`; any absence or mismatch tears the call down as a possible MITM. |
| **Anti-downgrade SDP gating** | A DTLS/SAVPF offer is never answered as plain RTP/AVP, and a plain answer to a DTLS offer is rejected, so media never connects silently insecure. |
| **Encryption never bridged** | Direct media is force-disabled on any SRTP/DTLS leg, so keys are never relayed to a non-secure peer. |
| **Documented concurrency model** | A single canonical lock order (`channel → pvt → peer`), single-owner Sofia thread, snapshot-under-lock off-thread, reload UAF fixes, and foreign-thread `nua_*` marshalling. |

---

## Engineered for large workloads — carrier scale

`chan_sofia` is built for high-volume, carrier-grade deployments, not just small installs.

- **Lean concurrency.** A **single Sofia event thread** owns all mutable signaling state and runs every callback, complemented by a **small fixed I/O pool** — not a thread per peer. This keeps context-switching and lock contention flat as registrations climb into the tens of thousands.
- **O(1) hash tables with fast XXH3-64 hashing.** Peer, dialog, presence and registration lookups are constant-time hash lookups dimensioned (all prime bucket counts) for carrier-scale populations, so call setup does not slow down as the system fills. The string hash behind every table is **XXH3 (64-bit)** — markedly faster on the short keys a PBX hashes than the classic byte-wise hash, with equal-or-better distribution and no external dependency. Measure it live with **`core test hash`** (reports Mhash/s, MB/s and ns/hash), and inspect live table health — buckets, load factor, longest chain, collisions and chi-squared — with **`core show ao2`** (every core container) and **`sip show hashstats`** (chan_sofia's own peer/dialog/presence/by-IP tables). The by-source-IP trunk index is specialized to static-host trunks for unambiguous, safe IP-trunk identification.
- **Bounded register pool under storms.** A bounded background worker pool absorbs realtime registration write-backs off the event thread, with OOM-safe drop semantics (the next REGISTER refreshes a dropped update) so a registration storm cannot stall signaling or exhaust memory.
- **A lean high-throughput media engine.** A single forked RTP engine carries both plain SIP and WebRTC media on a tight datapath, with the WebRTC demux path dormant until DTLS is active so non-WebRTC RTP pays no overhead.

The result is a SIP driver whose resource use scales with **work**, not with **endpoint count** — the property a carrier deployment depends on.

---

## Hardened and security-audited

`chan_sofia` is engineered to be exceptionally robust, and it has been **hardened and security-audited** through a **rigorous, multi-round adversarial review** of its correctness, concurrency and security posture.

That review repeatedly stressed the driver's reject paths, its lock ordering and lifetime management, and its authentication, transport-security and media-security gates — catching and closing defects that conventional testing rarely surfaces. The hardening is reflected throughout: validate-then-commit SDP that leaves an established call untouched when a re-INVITE fails any gate; fail-closed authentication, ACL and fingerprint checks; a documented single-owner concurrency model with one canonical lock order; and an anti-downgrade media posture in which encryption never silently falls back to plaintext.

The outcome is a SIP channel you can put in front of the public internet and trust at scale.

---

## Standards & RFC compliance

GABPBX 1.2 is a security-hardening release for `chan_sofia`. Every hardening gate below is anchored to the governing standard; the quoted clauses are the load-bearing normative text, verbatim.

### SIP authentication
- **Digest replay defense** — `qop=auth` nonce-count accounting is validated so a captured Authorization header cannot be replayed. RFC 2617 §3.2.2 (lines 657-659): *"if the same nc-value is seen twice, then the request is a replay."* RFC 7616 §3.4 (lines 536-539): *"to allow the server to detect request replays … if the same nc value is seen twice, then the request is a replay."*
- **`uri=` bound to the Request-URI** — RFC 2617 §3.2.2.5 (lines 806-808): *"The authenticating server must assure that the resource designated by the 'uri' directive is the same as the resource specified in the Request-Line; if they are not, the server SHOULD return a 400 Bad Request error."* RFC 7616 §3.4 (lines 711-713).
- **Out-of-dialog MESSAGE authenticated** — RFC 3428 §11 (lines 717-719): *"UAs that support the MESSAGE request MUST implement end-to-end authentication, body integrity, and body confidentiality mechanisms."*

### WebRTC media security
- **No cleartext media before DTLS** — RFC 8827 §6.5 (lines 832-834): *"Media traffic MUST NOT be sent over plain (unencrypted) RTP or RTCP."*
- **Fingerprint is the trust anchor (fail-closed)** — RFC 5763 §5 (lines 436-437): *"The integrity of the certificate is ensured through the fingerprint attribute in the SDP."*
- **Reject `a=setup:actpass` in an answer** — RFC 5763 §5 (lines 514-517): *"The answerer MUST use either a setup attribute value of setup:active or setup:passive."*

### WebRTC DataChannel (SCTP-over-DTLS)
- **DTLS-role stream parity** — RFC 8832 §6 (lines 322-324): *"If the side is acting as the DTLS client, it MUST choose an even stream identifier; if the side is acting as the DTLS server, it MUST choose an odd one."*
- **Ordered until acknowledged** — RFC 8832 §6 (lines 354-360): *"before the DATA_CHANNEL_ACK message … all other messages containing user data … MUST be sent ordered."*
- **SCTP restart handled distinctly** — RFC 6458 §6.1.1 (lines 2426-2437) / RFC 4960 §5.2.4 (lines 3818-3819).

### SDP offer/answer
- **Answer m-lines match the offer by order; reject with port 0** — RFC 3264 §6 (lines 468-472, 479-481): *"there MUST be a corresponding 'm=' line in the answer … matched up based on their order"*; *"To reject an offered stream, the port number … MUST be set to zero."* RFC 8829 §5.3.1 (lines 2402-2406).

### SIP signaling robustness
- **SUBSCRIBE expiry floor (423)** — RFC 6665 §4.2.1.1 (lines 959-964): the notifier *"MAY return a 423 (Interval Too Brief) error that contains a 'Min-Expires' header field."*
- **rtcp-mux demux by payload type** — RFC 5761 §4 (lines 217-222).
- **PUBLISH soft state; SIPS over TLS** — RFC 3903 §3 (lines 214-216); RFC 3261 §26.2.2 (lines 13366-13370) + §19.1.1 (lines 8485-8486): *"For sips:, it is TCP."*
- **`;lr` loose-route detection** — RFC 3261 §19.1.1 (lines 8407-8411).

---

## Building from source

GABPBX uses the standard Asterisk source workflow (`./configure && make menuselect && make && make install`). Beyond the usual Asterisk build dependencies, `chan_sofia` adds a few of its own.

| Dependency | Needed for | Debian/Ubuntu |
| --- | --- | --- |
| **Sofia-SIP 1.13.17**, built from source into `/usr/local` | `chan_sofia`'s SIP stack — **not a distro package** | tag `v1.13.17` from [garacil/sofia-sip](https://github.com/garacil/sofia-sip) (a fork of [freeswitch/sofia-sip](https://github.com/freeswitch/sofia-sip)) |
| OpenSSL | TLS, DTLS-SRTP, WebRTC, SHA-256 auth | `libssl-dev` |
| libsrtp2 | SRTP / DTLS-SRTP media | `libsrtp2-dev` |
| usrsctp *(optional)* | WebRTC DataChannel (SCTP-over-DTLS) | `libusrsctp-dev` |
| libopus | Opus codec (WebRTC) | `libopus-dev` |
| Standard Asterisk deps | core build | `build-essential pkg-config libedit-dev libjansson-dev libxml2-dev libsqlite3-dev uuid-dev libncurses-dev zlib1g-dev` |
| libpq *(optional)* | PostgreSQL realtime / CDR | `libpq-dev` |

**Sofia-SIP is the one non-obvious requirement.** `chan_sofia` links against `/usr/local/include/sofia-sip-1.13` and `/usr/local/lib/libsofia-sip-ua`, so install Sofia-SIP **before** building GABPBX, or `chan_sofia` fails with `fatal error: sofia-sip/nua.h: No such file or directory`.

```sh
# 1) Sofia-SIP into /usr/local (do this first)
git clone https://github.com/garacil/sofia-sip.git && cd sofia-sip
git checkout v1.13.17          # the stable release chan_sofia is built + tested against
./bootstrap.sh                 # only if ./configure is missing from the checkout
./configure --prefix=/usr/local && make && sudo make install && sudo ldconfig

# 2) GABPBX
cd /path/to/gabpbx
./configure
make menuselect.makeopts       # build menuselect first; avoids a -j race in its bundled mxml
make -j$(nproc)                # if a parallel build ever trips on menuselect/mxml, just re-run make
sudo make install
```

Full step-by-step — the Debian 13 recipe, the Sofia-SIP build, the per-module dependency map, and troubleshooting — is on the wiki: **[Build and Installation](https://github.com/garacil/gabpbx/wiki/Build-and-Installation)**.

---

## License

GABPBX is distributed under the GNU General Public License v2 (GPLv2). Existing Asterisk, Digium and third-party copyright notices and license terms are preserved in the source files where they apply.

— Germán Luis Aracil Boned
