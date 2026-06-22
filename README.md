# GABPBX

GABPBX is the Germán Aracil Boned PBX: a GPLv2 open-source PBX and telephony
toolkit maintained by Germán Luis Aracil Boned <garacilb@gmail.com>.

The project was first created in **2008** and is based on the **Asterisk 1.8**
codebase, later updated to the final stable 1.8 release. GABPBX keeps the proven
Asterisk architecture, dialplan, AMI and realtime APIs where they are useful, and
puts its new engineering where it matters most today: a modern, hardened SIP
channel driver. Existing Asterisk, Digium and third-party copyright notices and
the GPLv2 terms are preserved in the source files where they apply.

---

## GABPBX 1.1.1 — meet `chan_sofia`

`chan_sofia` is the headline of this project: a **modern SIP channel driver built
on the battle-tested [Sofia-SIP](https://github.com/freeswitch/sofia-sip) NUA
stack**, written as a **drop-in replacement for the aging `chan_sip`** — and then
taken well beyond it.

Migration is usually two lines:

```ini
; /etc/gabpbx/modules.conf
noload => chan_sip.so
load   => chan_sofia.so
```

Your dial plans, `sip show …` CLI muscle memory, `SIPpeers` / `SIPshowpeer` AMI
integrations, the `sippeers` realtime family and the `SIPPEER` / `SIP_HEADER`
dialplan functions all keep working — now on a maintained SIP stack with a real
transaction layer underneath. (`chan_sofia` and `chan_sip` register the same
public names, so load one or the other per instance, not both.)

## Why `chan_sofia` is special

**A real SIP stack, not a hand-rolled parser.** Sofia-SIP gives `chan_sofia` a
proper transaction state machine, multi-transport handling and RFC-correct
message construction — the same library lineage that powers large-scale
softswitches. `chan_sofia` adds the PBX behaviour on top and stays out of the
stack's way.

**Lean and concurrent by design.** Signalling runs on a single Sofia event thread
plus a small fixed I/O pool — not a thread per registration or per TLS connection —
so a few threads carry thousands of peers. Per-peer and per-call state is compact
and reference-counted, peer/dialog lookups are O(1) hash tables sized for carrier
load, and under a registration storm the realtime database writes can be handed to
a bounded worker pool (`register_pool`) so the signalling thread never blocks.

**Hardened on purpose.** `chan_sofia` went through a deep, multi-round correctness
and concurrency campaign: one canonical lock order (channel → pvt → peer), the
snapshot-under-lock discipline everywhere off the Sofia thread, teardown-race and
reload use-after-free fixes, a validate-then-commit SDP engine (a rejected
re-INVITE never disturbs the live call), bounded SDP build buffers, and SRTP
applied only after the offer is accepted — all verified under a concurrency stress
harness with `DEBUG_THREADS`.

## What it does — and where it surpasses `chan_sip`

Everything you expect from a SIP channel, plus capabilities `chan_sip` never had
(★ = beyond `chan_sip`):

**Registration & trunking**
- Inbound registrar + outbound `register =>` trunks with working digest auth,
  `sip show registry`, `sip unregister <peer>`.
- ★ **RFC 5626 SIP Outbound** (`sip_outbound`), ★ **RFC 3327 Path** (`path=yes`),
  ★ **RFC 3608 Service-Route** ingestion, ★ **GRUU** (`+sip.instance`, pub-GRUU as
  the dialog Contact).

**Call signalling**
- ★ **RFC 3262 reliable provisionals / PRACK** (`rel100`), ★ **RFC 3311 in-dialog
  UPDATE**, ★ **RFC 3326 Q.850 Reason** on BYE/CANCEL, REFER transfer, and
  out-of-dialog **SIP MESSAGE** (SIMPLE).

**Presence, BLF & voicemail**
- Inbound SUBSCRIBE → NOTIFY for dialog-info / PIDF (BLF), device-state on call
  transitions, both **solicited and ★ unsolicited MWI** (`subscribemwi`).
- ★ **Outbound PUBLISH (RFC 3903)** — publish local state to a central presence
  server; ★ **generic outbound SUBSCRIBE** for any event package; ★ **outbound MWI
  SUBSCRIBE watcher** that mirrors an upstream voicemail server's lamps locally.

**Media**
- Full codec negotiation (including Opus), **SDES-SRTP**, **T.38 fax**, direct
  media, per-peer RTP timeouts, and ★ **`media_address`** to advertise media on a
  different interface than signalling.

**Security & transport**
- UDP / TCP / TLS, ★ **mutual TLS** (`tlsverifyclient`) and TLS hardening
  (`tls_min_version`, `tls_ciphers`, `tls_verify_depth`), ★ **TCP keepalive**
  (`tcp_keepalive` / `tcp_pingpong`), digest auth with MD5 **and SHA-256**,
  anti-downgrade `qop`, source-IP and contact ACLs, and a REGISTER brute-force
  blacklist.

**NAT**
- `externip` / `externaddr` / `externhost` / `localnet`, `comedia`, `force_rport`,
  and registered-transport-aware routing so a TCP/TLS phone is reached over the
  transport it registered on.

**Diagnostics & operations**
- ★ **Per-call SIP history with a verbose call-analysis pass** (outcome, failure
  reason, timeline, negotiated codecs) + a source/destination capture filter and a
  retained ring that keeps a call inspectable *after hangup*.
- ★ **Caller→called on every log line.** GABPBX prefixes the main log with
  `[caller|called]`, so you can follow who is calling whom at a glance:
  ```text
  [alice|1000] Executing [1000@internal:1] Dial("SIP/alice-00000003", "SIP/1000")
  [alice|1000] SIP/1000-00000004 answered SIP/alice-00000003
  ```
- The complete realtime peer/registration model (`sippeers`, `sipregs`), and the
  `SIPpeers` / `SIPshowpeer` / `SIPqualifypeer` / `SIPnotify` AMI actions.

### CLI commands

```text
# Inspect
sip show peers                 sip show peer <name>
sip show settings              sip show registry
sip show channels              sip show channel <call-id>
sip show channelstats          sip show inuse [all]
sip show publications          sip show history [<call-id> [verbose]]
sip show blacklist

# Act
sip qualify peer <name>        sip notify <type> <peer>
sip unregister <peer>          sip reload
sip prune realtime [peer|all]
sip blacklist search|delete|clear <ip>

# Debug & history
sip set debug [on|off|peer <p>|ip <a>]
sip set history {on [<match>]|off}    sip history clear
```

`chan_sofia` lives in `channels/chan_sofia.c` plus a clean `channels/sofia/`
module tree (AMI, CLI, SDP, presence, T.38, PUBLISH, MESSAGE, transfer, GRUU,
subscribe, history). Every option is documented in `configs/sofia.conf.sample`
and on the [**project wiki**](https://github.com/garacil/gabpbx/wiki/Chan-Sofia).

## Quick start

```bash
# Debian 12 build deps (chan_sofia + Opus)
sudo apt install build-essential libncurses5-dev libjansson-dev libsqlite3-dev \
                 uuid-dev libxml2-dev libssl-dev libopus-dev libsofia-sip-ua-dev

./configure
make menuselect          # enable chan_sofia (Channel Drivers) + codec_opus
make
sudo make install        # add 'make samples' on a fresh box
```

Point `modules.conf` at `chan_sofia` (above), drop a peer in
`/etc/gabpbx/sofia.conf`, and start GABPBX:

```ini
[general]
udpbindaddr = 0.0.0.0:5060
context     = default

[1001]
type     = peer
host     = dynamic
secret   = change-me
context  = internal
mailbox  = 1001@default      ; unsolicited MWI by default (subscribemwi=no)
```

```text
gabpbx -c
*CLI> sip show settings
*CLI> sip show peers
*CLI> sip set history on
```

See the wiki [Build and Installation](https://github.com/garacil/gabpbx/wiki/Build-and-Installation)
page for the full walkthrough.

## Documentation

- **Wiki:** https://github.com/garacil/gabpbx/wiki — start at
  [Chan-Sofia](https://github.com/garacil/gabpbx/wiki/Chan-Sofia).
- **Sample config:** `configs/sofia.conf.sample` documents every knob.

## Roadmap

WebRTC media (DTLS-SRTP / ICE — pending an RTP-engine upgrade), richer
presence/dialog-event publishing, and continued scaling work. The signalling and
registration features above ship today.

## License

GABPBX is free software under the **GNU General Public License, version 2**.
Asterisk, Digium and third-party copyrights and licenses are retained in the files
where they apply.
