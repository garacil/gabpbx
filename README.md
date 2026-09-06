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

## GABPBX 1.6.0 — the star is `chan_sofia`

**`chan_sofia` is a complete, modern SIP channel driver built on the battle-tested [Sofia-SIP](https://github.com/garacil/sofia-sip) NUA stack — a true drop-in replacement for the aging `chan_sip`, with every `chan_sip` capability and a great deal more.** It is **feature-complete** and **security-hardened** — with **two-way WebRTC video** and **browser-to-browser DataChannels**. Release **1.3** makes the core **faster at scale**: the string hash that powers every internal hash table is now **XXH3-64**, the `chan_sofia` lookup tables are retuned for carrier load, and a new **`core test hash`** command lets you measure hash throughput on your own hardware. Release **1.3.1** selects the outbound media profile by each target's real transport (a WebRTC browser over wss gets DTLS-SRTP; a plain udp/tls phone gets RTP/AVP), so one account can be used from several phones of different technologies at once; **routes outbound calls to a NAT'd peer back to its learned public source** (a registered PBX or phone behind NAT now actually rings, instead of the INVITE being sent to an unreachable private address); and adds a configurable local-blacklist ban window (`blacklist_ban`, in minutes). Release **1.3.5** makes **inbound calls to a browser endpoint** (where GABPBX is the SDP offerer) connect with **two-way audio**: it repairs the ICE role conflict — a browser answering the offer would default to the controlled role, leaving both ends controlled and nobody nominating, so GABPBX now replies `487 Role Conflict` (RFC 8445 §7.3.1.1) to flip the browser to controlling — and it defers the DTLS handshake until the answer's `a=fingerprint` arrives, so an early `ClientHello` no longer fails the call. It also ships a `sip set debug sdp` SDP/ICE tracer and tags every SIP debug line with its `[from|to|callid]` transaction identity. Release **1.4.0** brings the WebRTC media path to a reliable baseline: audio latches immediately on every integrity-authenticated ICE check (removing the intermittent one-way / delayed audio and the offerer-inbound deaf case), video is negotiated over a single bundled ICE/DTLS transport (`a=group:BUNDLE`, RFC 8843; opt-in `webrtc_video_bundle`), DTMF reaches full `chan_sip` parity, the registrar implements per-Contact REGISTER bindings (RFC 3261 §10.3), TLS accepts 1.2 by default, and — since ws/wss/tls SIP is encrypted on the wire — GABPBX can **stream every SIP message decrypted** to a Homer/**HEP** collector or a plain-text file (`sip_capture_address` / `sip_capture_file`, or the runtime `sip set debug capture` / `file`), alongside default-off `rtp set debug ice` and `sip set debug fork` tracers that open a window into the WebRTC media and call-fork lifecycle. Release **1.4.1** fixes a WebRTC call-forking media failure — when a call forks to an extension registered from both a WebRTC browser and a plain phone and the browser wins, the call now carries two-way audio and video (previously the winner leg's DTLS never completed because stale media descriptors starved its audio socket) — and adds **native peer-to-peer SIP text messaging**: an out-of-dialog `MESSAGE` between two registered users is now delivered to the recipient's live devices (resolved through the same auto-created hint namespace as BLF), instead of being answered `405` (`message_autorelay`, on by default). Release **1.4.2** overhauls **WebRTC call hold/resume**: SDP answers now mirror the offered per-media direction (RFC 3264 §6.1) and every offered m-line (current-transaction role), so pressing Hold on a WebRTC phone no longer tears the call down; stream identity and video payload types stay stable across renegotiation; and full **RTCP keyframe feedback** (PSFB PLI/FIR, RFC 4585/RFC 5104) is implemented end-to-end — advertised in SDP, relayed across the bridge, and transmitted SRTCP-protected over the ICE tuple — so **video resumes by itself on unhold**, exactly like audio. Release **1.4.3** fixes NAT/media routing to match `chan_sip`: `force_rport` now governs SIP response routing only (RFC 3581) and no longer redirects RTP — the media-destination override applies with `comedia` (symmetric RTP) only — so a trunk fronted by a signaling-only SIP proxy (e.g. Kamailio without an RTP relay) keeps sending audio to the real SDP endpoint instead of the proxy; and a `[general] nat` setting is now inherited by peers (including empty realtime `nat` columns) that have no explicit `nat=` line. Releases **1.5.0–1.5.11** add **two-way SIP-video ↔ WebRTC-video bridging**, WebRTC hold/resume, native SIP `MESSAGE` relay, chan_sip-parity caller-ID and legacy digest (`auth_qop`) handling, and two audit-hardening batches. Release **1.5.12** is a **focused security-hardening release** from a full `chan_sofia` audit: it closes a remote unauthenticated memory-exhaustion leak on out-of-dialog `OPTIONS` keep-alives and bounds the inbound WebRTC DataChannel receive queue; makes `alwaysauthreject` truly indistinguishable for existing vs non-existent accounts (in status **and** timing) and ensures delayed authentication rejections are actually transmitted; parses stateless auth nonces strictly; reads channel identity under the channel lock to close a masquerade-race use-after-free; and rejects a malformed or out-of-dialog `REFER` before the `202 Accepted` instead of orphaning a transfer subscription — eight fixes in all, with no configuration or behavior change for a correctly-configured deployment. Release **1.5.0** bridges **two-way video between a legacy SIP video phone and a WebRTC leg** by pure passthrough (no transcoding): the answer sent to the caller is now narrowed to the video codec the far/bridge leg actually negotiated (RFC 3264 §6) — codecs the far leg cannot produce are dropped rather than merely reordered, so a phone no longer locks its video onto a payload type the browser will never send — with H.264 `a=fmtp` (`profile-level-id` / `packetization-mode`, RFC 6184 §8.2.2) relayed across the two legs and a fail-closed to audio when no common video codec exists; a keyframe request now crosses the bridge in both directions (SIP INFO `picture_fast_update` ⇄ RTCP PLI/FIR, RFC 5168), and the SIP INFO answer is bound to its own transaction (`NUTAG_WITH_THIS`), removing a spurious ~32-second call teardown. 1.5.0 also honours **SDP `o=` version stickiness** (RFC 3264 §8, `ignoresdpversion`): a re-offer repeating the same session origin with an unchanged version is a no-op, so a NAT caller's learned public media address survives an `UPDATE`/re-INVITE keepalive (matching `chan_sip` `process_sdp_o`); adds **`sip set debug dtmf on|off`** to log every received DTMF digit (RFC 2833/INFO/inband) to the CLI and messages log, as `chan_sip` did; and ships several robustness fixes (module unload is refused before any teardown; the legacy video RTP instance uses the module scheduler; the PRACK 200 and the SIP-capture CLI changes are bound/marshalled correctly; and a redundant manual 200 to BYE/CANCEL is removed). Release **1.5.1** fixes a `sip reload` reliability regression: on a config with no explicit `tls_min_version=` line, the reload check compared the running effective default (TLS 1.2) against an empty scratch default and flagged a phantom listener change, refusing every `sip reload` with `listener config changed (tls_min_version)` until a restart — the scratch now seeds the same effective default (shared with the load path so they cannot drift), while a genuine change such as `tls_min_version=1.3` is still correctly detected as needing a restart. Release **1.5.2** adds **`auth_qop`** — a legacy no-`qop` RFC 2069 MD5 digest challenge for older SIP stacks that reject a `qop="auth"` challenge (default off = `chan_sip` parity, no replay protection; on = RFC 2617 `qop=auth`). Release **1.5.3** presents the matched peer's configured **`callerid`** on the outbound `From` (`chan_sip` parity) instead of the raw SIP username that could be rejected upstream, via a new **`apply_peer_callerid`** (default on); it also repairs peer `callerid=` parsing so the value is split into caller-id number/name. Release **1.5.4** stops the outbound `From` from ever leaking the **peer/section name** on an anonymous call and adds **`[general] callerid`** as the last-resort From identity (`chan_sip` `default_callerid` parity). Release **1.5.5** makes a peer's **`fromuser`** an **override** of the outbound `From` user — winning over the resolved caller-ID (`chan_sip` `initreqprep` parity) — so a trunk-provisioned identity is presented when the peer has no `callerid`, while `RPID`/`PAI` and the display name are untouched. Release **1.5.6** is an **audit-hardening** batch: `sdp_crypto` never logs the inline **SRTP master key** (RFC 4568 §9.1); in per-suite-key mode the advertised `a=crypto` key now matches the installed local policy, and the unchanged-crypto short-circuit compares suite + selected index + key (not the key bytes alone); the scheduled RTCP SR/RR and the video-update **PLI** now serialize on the SRTCP session; **T.38** parameter interpretation and the **late-offer ACK** SDP parse run under the proper lock; outbound-call paths no longer read freeable peer string fields during a `sip reload`; an **unanswered inbound INVITE** is rejected with a hang-up-cause-mapped final response instead of `CANCEL` (`chan_sip` parity, with a guard against a double final); in-dialog **UPDATE**/**NOTIFY** responses are bound to their server transaction so the reply reaches the wire; and a **forked** call's winner clears the peer ringing state so BLF moves RINGING → INUSE. Release **1.5.7** continues the **audit-hardening** with a focus on concurrency and media-negotiation correctness: the per-instance **RTP codec payload map** and the outbound **SRTP** protect/send now serialize with the media threads under the RTP instance lock (the peer-to-peer bridge takes its two instance locks separately so opposite directions cannot deadlock); `sdp_crypto` never logs the local SRTP master key, zeroizes key material on teardown, and rejects an over-long inline key (RFC 4568 §9.1); a WebRTC answer lists the `a=group:BUNDLE` mids in the **offered m-line order** (RFC 8843 §7.3.1) and the mid/group buffers are sized for standards-legal long mids; an **image-only T.38** re-INVITE is answered with `m=image` only (RFC 3264 §6); a re-INVITE on a leg that offered WebRTC video keeps offering it; a **forked** call applies its winning branch's negotiated audio codec to the answered channel; and a set of smaller robustness fixes (compound-RTCP keyframe preservation, native-bridge video/text address baselines, `blacklist_ban` overflow clamp, REGISTER-reject response binding, and per-peer lock cleanup). Release **1.5.8** grows the SDP build buffers so a WebRTC video answer with BUNDLE, multiple payload types and their per-payload `a=rtcp-fb` lines plus ICE candidates is no longer dropped when it exceeds the previous 2048-byte buffers (RFC 8843/6184); makes `progressinband=no` a distinct state from `never` (RINGING degrades to in-band ringback once a 183 has been sent, `chan_sip` parity); aggregates MWI `application/simple-message-summary` counts across all message classes (RFC 3842 §2.2); and selects the reception-report block that concerns our own SSRC from a multi-block RTCP SR/RR (RFC 3550 §6.4.1). Release **1.5.9** stamps a **Q.850 Reason** header (RFC 3326) on INVITE-rejection responses (404/480/484/486/488/503 and the in-dialog re-INVITE/UPDATE/T.38 rejects), not only on BYE/CANCEL, so upstream proxies and billing see the real cause (`use_q850_reason`, default no; the cause is mapped from the SIP status via a port of `chan_sip`'s `hangup_sip2cause`). Release **1.5.10** adds **forked-call early media** (experimental, `fork_early_media`, default off): once a forked call narrows to a single live non-WebRTC branch that sends a 180/183 with SDP, the caller hears that branch's early media (receive-only) instead of staying muted until answer. Release **1.5.11** adds a **local-hold offer direction** (experimental, `hold_reinvite`, default off): a local hold can now re-INVITE the peer to `a=sendonly` (peer hears our music-on-hold, RFC 6337) or `a=inactive`, restoring `a=sendrecv` on unhold, instead of playing MOH only — with a typed re-INVITE purpose that keeps directmedia, T.38 and local-hold response handling isolated. Both 1.5.10 and 1.5.11 ship off by default; their enabled paths are validated end to end in a controlled test and stay off pending production soak. Release **1.5.13** closes a related memory-exhaustion leak surfaced by the 1.5.12 audit: an out-of-dialog request dropped by the IP blacklist — under exactly the brute-force the blacklist defends against — leaked the protocol handle the stack had created for it (every method except `OPTIONS`, and `SUBSCRIBE` even leaked a dialog leg), so a sustained attack grew memory without bound while the box was under fire; the blacklist drop path now reaps the handle for every method. Release **1.5.14** adds a **`sip show version`** CLI command that reports which Sofia-SIP library `chan_sofia` is using — the compile-time version it was built against, the runtime version exported by the shared object actually loaded (so a value that differs flags a library newer or older than the headers `chan_sofia` was compiled with), and the resolved path of that shared object. Release **1.5.15** fixes two presence/BLF counter-and-Contact bugs that made watched-extension lamps go stale. First, **BLF subscriptions no longer die at their first refresh**: the SUBSCRIBE-dialog `Contact` that GABPBX handed a watcher used a non-routable wildcard user-part (`<sip:*@…>`), so the phone refreshed in-dialog to `SUBSCRIBE sip:*`, which GABPBX answered `404`/tore down as `terminated;reason=timeout` — every `Event: dialog` subscription established, then collapsed on its first renewal, so watcher counts never reached a full mesh; the `200`/`202` and the `NOTIFY` now carry a routable `Contact: <sip:<watched-exten>@…>` so refreshes route back and the subscription persists. Second, the **on-hold device state no longer sticks busy**: the per-peer on-hold counter was incremented when a call was placed on hold but never decremented if the call was hung up or transferred *while still on hold*, so a single leaked count pinned `SIP/<peer>` `ONHOLD` (which outranks in-use in the device-state calculation) with zero live channels — BLF watchers then saw the extension permanently busy; the counter is now released on every teardown path, tracked independently of a mid-call `notifyhold` reload. Release **1.5.16** makes **BLF work automatically for every configured extension**, including ones that have not registered yet, and fixes a bug where watched-extension hints were created but never resolvable (`core show hints` showed duplicated hints with `Watchers 0` while the lamps stayed dark). The hint was being placed with `ast_context_find_or_create()`, a check-then-act that under a same-name race stranded the hint on a list-only *orphan* context the presence lookup (which reads the context hashtab only) never resolves. `chan_sofia` now adds the hint **by context name** with `ast_add_extension()` — resolving the authoritative context atomically, so the hint lands exactly where the lookup finds it and survives a dialplan reload — creating the BLF context once only if the dialplan does not define it (an already-defined context is never re-created and so never duplicated). A `SUBSCRIBE` to a configured peer whose hint does not exist yet now **materializes it on demand** (build the peer, create the hint synchronously, re-check) so it is answered `202` instead of `404`; the hint context resolves `subscribecontext` first, else the peer `context`. Release **1.5.17** restores faithful `${HANGUPCAUSE}` across the call bridge: after a normally-answered call that the **called party** hangs up, the caller's `${HANGUPCAUSE}` was left `0` instead of the real cause, so a carrier-failover dialplan that ends its retry loop on `$[${HANGUPCAUSE}=16]` mistook the completed, billable call for a failure and re-dialed the next carrier (a double-call / double-billing bug) — `ast_bridge_call()` now propagates the hung-up party's cause to the surviving channel exactly as modern Asterisk's bridging framework does (`bridge_dissolve` → `channel_set_cause`: preserve an existing positive cause, normalize an unknown real hangup to `NORMAL_CLEARING`, no-op on feature/time-limit returns), so `chan_sofia` regains the `chan_sip` behavior it had been missing — `${HANGUPCAUSE}` is `16` after any normally-answered call regardless of which side hangs up — while busy / no-answer / congestion / reject (which never reach the bridge) still fail over normally. Release **1.6.0** brings **mobile push wake-up**: a call to a mobile extension whose app is killed or asleep no longer fails — `chan_sofia` captures each device's push token at REGISTER (`X-Push-Token`/`X-Device-ID`, stored in a local SQLite realtime store with an in-memory cache so the dial path never touches a database), **parks the call, wakes the phone** through APNs VoIP / FCM v1 sender scripts announcing a pre-generated Call-ID, and **resumes the parked call to the fresh binding the moment the device re-registers** — wake REGISTER measured 1–2 s after the push on real devices, with a clean `NOANSWER` fallback, automatic dead-token purge, per-peer opt-out and a `sip show push` CLI; peers without tokens behave exactly as before. Release **1.7.0** extends push wake-up to the **suspended-app black hole**: an app frozen by the OS with its connection-oriented binding (tcp/tls/ws/wss) still live swallows the INVITE silently until Timer B — now every outbound INVITE to a tokened peer carries a pre-generated Call-ID, and if **no provisional arrives within 4 seconds** (`push_noresponse`) the call parks in-flight and the push goes out announcing the Call-ID already on the wire; the wake REGISTER swaps the leg (the old one is detached first — no CANCEL ever hits the wire, and a late 408/487 cannot touch the live call) and re-INVITEs the fresh binding with the **same Call-ID** so the phone dedupes the two paths into one incoming-call card, while a provisional that arrives late simply unparks the entry and lets the original leg win. It also makes push wake-up **multi-device correct**: the first wake REGISTER opens a short collect window (`push_resume_window`, default 2 s) and the resume then forks **one INVITE per live binding** — every branch carrying the announced Call-ID — so every woken device rings and the first to answer takes the call while the rest get a real CANCEL; a device that only registers after the user accepts the push card (10-30 s later) still gets its branch **appended while the call rings** and can win it. Release **1.8.0** adds call-control and media fixes: dialing your **own extension** now rings your *other* devices and never the one placing the call (matched by INVITE source or `+sip.instance`, surviving a NAT rebinding; `busy_on_active` ignores the caller's own binding so an autocall is not answered busy); a **bridge between two SRTP/WebRTC legs** is no longer deaf — `sofia_get_rtp_peer` returns `FORBID` for an SRTP leg (chan_sip parity) so the core's generic bridge regenerates each RTP packet under the far leg's own SSRC/sequence instead of the P2P relay that broke SRTP auth; **`rtptimeout`/`rtpholdtimeout`/`rtpkeepalive` are now enforced** by a 2-second inactivity sweep (a peer that vanishes mid-call without a BYE is torn down instead of lingering); an **attended transfer whose consult leg is an application** (IVR/echo/voicemail) completes instead of returning 486; and a **DTLS-SRTP keying race** that cost ~10 s of dead audio at answer (the callee's ClientHello beating our parse of its SDP fingerprint) is closed by deferring the verify until the fingerprint arrives.

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
| **CLI — `sip show …`** | `sip show peers`, `sip show peer <name>` (a concise, friendly summary — registration, endpoint, context, media, calls, qualify — followed by the per-contact list; `sip show peer <name> detail` for the full per-field dump, tab-completed), `sip show settings`, `sip show version`, `sip show registry`, `sip show channels` / `channelstats`, `sip show inuse` — chan_sip's column layout, snapshotted under lock. |
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
| **Sofia-SIP 2.0.4**, built from source into `/usr/local` | `chan_sofia`'s SIP stack — **not a distro package** | tag `v2.0.4` from [garacil/sofia-sip](https://github.com/garacil/sofia-sip) (a fork of [freeswitch/sofia-sip](https://github.com/freeswitch/sofia-sip)) — a **warning-clean build on GCC 14 / OpenSSL 3** (soname unchanged, `0.6.0`) |
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
git checkout v2.0.4  # the release chan_sofia is built + tested against (warning-clean on GCC 14 / OpenSSL 3)
./autogen.sh                   # generate ./configure on a fresh clone (./bootstrap.sh also works)
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
