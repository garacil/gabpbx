# GABPBX

GABPBX is the Germán Aracil Boned PBX: a GPLv2 open source PBX and
telephony toolkit maintained by Germán Luis Aracil Boned
<garacilb@gmail.com>.

The project was first created in 2008 and is based on the Asterisk 1.8
codebase, later updated to the final stable Asterisk 1.8 release. GABPBX keeps
the proven Asterisk architecture and APIs where they are useful, while adding
new production work focused on SIP, realtime operation, codec support and
carrier-grade PBX deployments.

Existing Asterisk, Digium, third-party copyright notices and GPL licensing
terms are preserved in the source files where they apply.

## What GABPBX Provides

GABPBX is a complete PBX platform for VoIP and traditional telephony. It
includes:

- SIP telephony with the new `chan_sofia` Sofia-SIP channel driver.
- Legacy SIP compatibility through the same public `SIP` technology name.
- Dialplan applications, functions, bridging, voicemail, queues, CDR/CEL,
  AGI, AMI, realtime configuration and media translation.
- PostgreSQL realtime support, including cache-aware `res_config_pgsql`
  operation.
- RTP media handling, NAT support, SRTP support and session timer support.
- Opus codec support through `codec_opus` and `libopus`.
- Traditional codec support such as alaw, ulaw, GSM, G.729 passthrough,
  Speex and signed linear formats, depending on selected modules and local
  libraries.

## chan_sofia

`chan_sofia` is the modern SIP channel driver for GABPBX. It is built on the
Sofia-SIP NUA API and is designed as a drop-in replacement for `chan_sip`, while
using a stronger SIP stack instead of duplicating low-level SIP parsing and
transaction handling by hand.

The compatibility policy is deliberate:

- The channel technology name is still `SIP`.
- Existing dialplans can continue to use `Dial(SIP/peer)` syntax.
- The realtime family remains `sippeers`.
- Existing SIP CLI names are preserved, such as `sip show peers`,
  `sip show peer <name>`, `sip show channels` and `sip set debug`.
- Existing AMI names are preserved, including `SIPpeers`, `SIPshowpeer`,
  `SIPqualifypeer`, `SIPshowregistry` and `SIPnotify`.
- Existing dialplan functions are preserved where implemented, including
  `SIPPEER`, `SIPCHANINFO`, `SIP_HEADER` and `CHECKSIPDOMAIN`.

`chan_sofia` and `chan_sip` must not be loaded at the same time. They register
the same public technology, CLI, AMI and realtime names. To use `chan_sofia`,
disable `chan_sip.so` in `modules.conf`, enable `chan_sofia.so`, then restart
GABPBX.

Example:

```ini
; /etc/gabpbx/modules.conf
noload => chan_sip.so
load => chan_sofia.so
```

### chan_sofia Feature Map

Protocol and channel behavior:

- Sofia-SIP NUA based SIP stack integration.
- Public channel technology remains `SIP`.
- Inbound and outbound INVITE call setup.
- ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO,
  PUBLISH and PRACK handling through Sofia-SIP method dispatch.
- Blind and attended transfer handling through SIP REFER and GABPBX bridge
  integration.
- SIP dialog tracking through internal `ao2_container` registries.
- Channel state integration with GABPBX core.
- Overlap dialing support with `allowoverlap`.
- RFC 3261 Max-Forwards support.
- RFC 4028 session timer support.
- Per-peer and global session timer policy:
  `session-timers`, `session-expires`, `session-minse`,
  `session-refresher`.
- SIP T1 and Timer B global configuration through Sofia-SIP native timers.

Transport and listener support:

- UDP listener.
- TCP listener.
- Optional TLS listener.
- Optional WebSocket listener for SIP signaling.
- Optional Secure WebSocket listener for SIP signaling.
- Configurable bind address and bind port.
- TLS certificate directory support using `agent.pem` and `cafile.pem`.
- WSS helper behavior to derive expected WSS certificate files from TLS files.
- SRV lookup support for outbound calls.
- Configurable outbound User-Agent.
- Reverse-proxy deployment guidance for WS/WSS origin enforcement.

Drop-in `chan_sip` compatibility:

- `Dial(SIP/peer)` continues to work.
- Existing `sippeers` realtime family is reused.
- Existing SIP CLI command names are reused.
- Existing SIP AMI action names are reused.
- Existing SIP AMI event names are preserved where compatible.
- Existing dialplan functions are preserved where implemented.
- `sofia.conf` follows the `sip.conf` style.
- Historical spelling compatibility is preserved for selected options, such as
  expiry typo variants.
- `chan_sofia` intentionally cannot coexist with `chan_sip` in the same
  process, because both register the same public SIP names.

Authentication and security:

- Digest authentication with MD5.
- Digest authentication with SHA-256.
- `qop=auth` support.
- RFC 2069 fallback when clients omit `qop`.
- Nonce TTL control.
- Stale nonce challenge handling.
- Nonce-count replay protection.
- `alwaysauthreject` support to prevent username enumeration.
- Optional global `force_invite_auth` lockdown behavior.
- Per-peer `insecure` behavior for compatibility with trusted trunks.
- Source IP ACL support.
- Contact-header ACL support with `contactpermit` and `contactdeny`.
- Direct-media ACL support with `directmediapermit` and `directmediadeny`.
- REGISTER User-Agent locking with `lockuseragent`.
- AMI visibility for authentication failures.
- AMI visibility for User-Agent lock rejections.
- Local SIP blacklist for repeated invalid REGISTER/authentication attempts.
- Blacklisted IPs are silently dropped instead of receiving a SIP response.
- Default local blacklist size is 1024 entries.
- Default blacklist threshold is 5 failures.

Registration:

- Registrar support for dynamic peers.
- Multi-contact registration support.
- Configurable `maxcontacts` with a hard ceiling.
- REGISTER expiry bounds:
  `minexpiry`, `maxexpiry`, `defaultexpiry`.
- RFC 3261 `423 Interval Too Brief` handling.
- Registration state persistence to realtime.
- Optional separated `sipregs` realtime registration table.
- Outbound registration support through register-style peers.
- Outbound registration retry controls:
  `registertimeout` and `registerattempts`.
- `callbackextension` support for outbound Contact URI user control.
- Peer source address tracking.
- Registered contact display in `sip show peer`.
- Registration AMI events.
- PeerStatus AMI events for registered/unregistered state.

Realtime and database operation:

- `sippeers` realtime family compatibility.
- Optional `sipregs` family for separating registration state from peer
  configuration.
- Runtime peer caching through `ao2_container`.
- `sip prune realtime` CLI support.
- PostgreSQL realtime cache documentation in `configs/res_pgsql.conf.sample`.
- Realtime peer display keeps the source visible as realtime/static.

NAT, addressing and DNS:

- `externaddr` support.
- `externhost` compatibility.
- `externrefresh` behavior.
- `localnet` support.
- rport/comedia style NAT operation.
- `nat=force_rport,comedia` style peer configuration.
- `directmedia` control.
- DNS manager integration for peers with hostname-based `host=`.
- AMI `DnsManagerUpdate` event when DNS-tracked peer addresses change.
- `matchexternaddrlocally` / `matchexterniplocally` are parsed and displayed
  for migration compatibility.

Media and RTP:

- RTP media integration through the GABPBX RTP engine.
- Static RTP payload support for classic codecs.
- Dynamic RTP payload support for modern codecs.
- Opus SDP support.
- Codec preference handling through normal `allow` / `disallow` lists.
- DTMF mode support.
- RFC 2833 / telephone-event style DTMF.
- Inband DTMF detection through GABPBX DSP where configured.
- `relaxdtmf` support.
- Hold detection and bridge hold signaling.
- Music-on-hold interpretation and suggestion fields.
- RTP timeout, RTP hold timeout and RTP keepalive configuration.
- Direct media decisions centralized in `sofia_get_rtp_peer`.
- Video direct-media is intentionally kept on the relayed path today.

SRTP and encryption:

- SRTP configuration support.
- SDP crypto helper integration.
- Configurable SRTP cipher display.
- Optional per-suite fresh SRTP key policy.
- Encryption defaults are conservative: unset encryption fields behave as
  disabled instead of accidentally enabling SRTP.

Identity and headers:

- Caller ID name/number propagation.
- `callingpres` support.
- `sendrpid` support.
- `trustrpid` support.
- Remote-Party-ID and P-Asserted-Identity handling.
- `usereqphone` support for `;user=phone` URI generation.
- Per-peer `setvar` support.
- Per-peer outbound SIP `header=` support through inherited channel variables.
- `SIPAddHeader` style dialplan behavior is preserved through the compatibility
  header path.

Call limits and usage counters:

- `callcounter` support.
- `call-limit` support.
- `busylevel` support.
- Busy-on-active support.
- In-use, ringing and on-hold counters.
- `sip show inuse` CLI.
- `SIPshowpeer` AMI fields for call usage.
- AMI PeerStatus events for call-limit rejection and call counter updates.

Transfers and REFER:

- SIP REFER handling.
- REFER policy through `allowtransfer`.
- Transfer rejection with SIP response and AMI visibility.
- AMI `Transfer` event integration.
- AMI `TransferRejected` event.
- AMI `ReferProgress` event on transfer progress notifications.
- Transfer mode display in CLI and AMI.

Subscribe, MWI and presence-related behavior:

- `allowsubscribe` support.
- Message-summary MWI SUBSCRIBE handling.
- MWI expiry configuration.
- `subscribecontext` is parsed, stored and displayed for compatibility.
- Unknown or unsupported subscription event packages are accepted according to
  current Sofia/GABPBX behavior, but full dialog/presence routing is future
  work.
- AMI `SubscribeRejected` event when subscription policy rejects a peer.

Fax and T.38 related behavior:

- T.38 fax UDPTL relay through the GABPBX `ast_udptl` engine.
- 4-state T.38 negotiation machine (disabled, local-reinvite, peer-reinvite,
  enabled) with peer-reinvite abort timer.
- SDP T.38 attribute negotiation: `T38FaxVersion`, `T38MaxBitRate`,
  `T38FaxRateManagement`, `T38FaxMaxBuffer`, `T38FaxMaxDatagram` and
  `T38FaxUdpEC` (FEC / redundancy / none).
- Per-peer `t38pt_udptl` configuration for enable, EC mode and
  `maxdatagram=` override.
- `[general]` `t38_maxdatagram` for the global default.
- Per-peer `t38pt_usertpsource` for symmetric-RTP UDPTL destination behavior
  on NAT'd peers.
- `AST_OPTION_T38_STATE` `queryoption` handler so applications such as
  `SendFAX` and `ReceiveFAX` can drive T.38 negotiation.
- AMI `T38FaxNegotiation` event on each state transition.
- `faxdetect` modes wired in: `no` (default), `cng` (DSP CNG tone detection),
  `t38` (peer T.38 reINVITE detection), `cng,t38` / `yes` (both). On detection
  the channel is async-redirected to the `fax` extension where the dialplan
  runs `SendFAX` / `ReceiveFAX`.
- `t38pt_udptl=no` peers stay on classic audio and the T.38 engine remains
  inactive for them.

CLI commands:

```text
sip show peers
sip show channels
sip show peer <name>
sip show inuse [all]
sip show settings
sip set debug [on|off|peer <name>|ip <addr>]
sip prune realtime [peer [<name>|all|like <pattern>]|all]
sip show blacklist
sip blacklist search <IP>
sip blacklist delete <IP>
sip blacklist clear
```

Example `sip show peer test` output from a local GABPBX instance:

```text
*CLI> sip show peer test
Setting max files open to 100000

==============================================================================
  SIP peer             : test
  Registration         : registered
==============================================================================
  Endpoint             : test@dynamic:5060 via udp
  Context / source     : killer / sofia.conf
  Contact slots        : 1 used of 6 allowed
  Media                : codecs=(opus|g722|alaw|g729) dtmf=rfc2833 nat=force_rport directmedia=No
  Calls                : 0/1 active, 0 ringing, 0 on-hold
  Qualify              : no
  Session timers       : originate, expires=3600, minse=90, refresher=uac
  Identity headers     : send=rpid, trust=No, presentation=allowed_not_screened

-- Identity ------------------------------------------------------------------
  Name                 : test
  Username             : test
  Type                 : peer
  Host                 : dynamic
  Port                 : 5060
  Transport            : udp
  Context              : killer
  Registered           : Yes
  Expires              : 360s
  Secret               : (set)
  Qualify              : no

-- Network and media ---------------------------------------------------------
  NAT                  : force_rport
  DTMF mode            : rfc2833
  Direct media         : No
  Encryption           : No
  Codecs               : (opus|g722|alaw|g729)
  Max call BR          : 384 kbps

-- Limits and features -------------------------------------------------------
  Busy on active       : No
  Max contacts         : 6 (used: 1)
  Transfer mode        : open
  Lock user-agent      : No
  Language             : es
  Default IP           : (null)
  AMA flags            : Unknown
  Subscribe MWI        : No
  Preferred codec      : No
  Ignore SDP ver       : No
  Promisc redir        : No
  Auto framing         : No
  Fax detect           : no

-- Fax and T.38 --------------------------------------------------------------
  T38 support          : No
  T38 EC mode          : FEC
  T38 max datagram     : -1
  T38 RTP source       : No

-- Timers and RTP ------------------------------------------------------------
  Timer B              : 32000
  Timer T1             : 500
  Overlap dial         : Yes
  RTP timeout          : 30
  RTP hold timeout     : 300
  RTP keepalive        : 0

-- Routing and dialplan ------------------------------------------------------
  Parking lot          : default
  User=Phone           : no
  Max forwards         : 70 (from [general])
  Mailbox              : (none)
  Outbound proxy       : (none)
  MOH interpret        : (none)
  MOH suggest          : (none)
  SRTP cipher          : (default AES_CM_128_HMAC_SHA1_80)

-- Session and identity headers ----------------------------------------------
  Session timers       : originate
  Session expires      : 3600
  Session Min-SE       : 90
  Session refresher    : uac
  Calling pres         : allowed_not_screened
  Send RPID            : rpid
  Trust RPID           : No
  Concurrent calls     : 0/1 (0 ringing, 0 on-hold)

-- Groups and source ---------------------------------------------------------
  Call group           :
  Pickup group         :
  Subscribe context    : <Not set>

-- Security and ACL ----------------------------------------------------------
  Insecure             : port,invite
  ACL                  : no
  Contact ACL          : no
  Direct media ACL     : no
  DNS managed          : no

-- Registration --------------------------------------------------------------
  Source               : sofia.conf
  Source addr          : 127.0.0.1:34549

-- Contacts ------------------------------------------------------------------
  Contact count        : 1
  Contact 1 URI        : sip:test@127.0.1.1:100
    State                : IDLE
    TTL                  : 3488s
    Source               : 127.0.0.1:34549
    User-Agent           : sipsak 0.9.8.1
```

AMI actions:

```text
SIPpeers
SIPshowpeer
SIPqualifypeer
SIPshowregistry
SIPnotify
```

AMI events include:

```text
PeerStatus
Registry
Hold
Transfer
ReferProgress
TransferRejected
AuthFailure
SubscribeRejected
LockUserAgentReject
RegisterIntervalRejected
RegextenOnQualifyTransition
DnsManagerUpdate
HintCreated
InsecureInviteBypass
SessionTimerRefresh
T38FaxNegotiation
```

### chan_sofia Future Roadmap

The project is conservative about roadmap claims: features listed here are not
presented as completed behavior unless the current source already wires them.
They are the next logical areas for public hardening and completion.

Planned or staged work:

- WebRTC media Stage B: DTLS-SRTP, ICE and BUNDLE media integration. Current
  WS/WSS work is SIP signaling oriented.
- Presence and dialog event-package handling.
- Runtime `subscribecontext` dispatch once the presence/dialog handler lands.
- Unsolicited MWI NOTIFY support if operator demand requires it.
- Full outbound HOLD re-INVITE generation, including outbound MOH suggestion
  signaling.
- Full `directrtpsetup` early-RTP bridge behavior. The option is parsed for
  migration compatibility today.
- Dynamic outbound Allow header generation from `disallowed_methods`.
- Compact SIP header emission if Sofia-SIP exposes a native compact-header
  control or the project carries a Sofia-SIP patch for it.
- 3xx redirect handling for `promiscredir`.
- `autoframing` SDP ptime/framesize wire-in.
- Exact `progressinband=no` chan_sip state-machine parity.
- Peer eviction behavior for `rtcachefriends=no` and `rtautoclear`.
- Per-peer dynamic T1 timer adjustment based on qualify RTT.
- Text RTP QoS handling for `tos_text` and `cos_text`.
- Video direct-media support after audio/direct-media behavior remains stable.
- Better clean-reload and clean-unload behavior where Sofia-SIP thread ownership
  permits it. For now, restarting GABPBX is the correct operational method after
  changing the active SIP channel driver.

The main configuration file is:

```text
/etc/gabpbx/sofia.conf
```

A detailed sample is provided in:

```text
configs/sofia.conf.sample
```

## Opus Codec Support

GABPBX includes native Opus translator support in `codec_opus`.

The module translates between Opus and signed linear audio using `libopus`.
The current implementation supports 8 kHz and 16 kHz signed linear paths and
uses Opus internally according to RFC 7587. Opus is especially useful for
WebRTC, modern SIP endpoints and low-bitrate high-quality VoIP.

Build dependency:

```text
libopus
pkg-config
```

On Debian or Ubuntu systems, the package is usually:

```sh
apt install libopus-dev pkg-config
```

Opus settings are configured in:

```text
/etc/gabpbx/codecs.conf
```

Sample configuration:

```ini
[opus]
bitrate => 32000
fec => true
dtx => false
```

To allow Opus on a SIP peer:

```ini
disallow=all
allow=opus
allow=alaw
allow=ulaw
```

Runtime CLI:

```text
*CLI> opus show
```

## Build Requirements

GABPBX is primarily built and tested on GNU/Linux.

Core build tools:

- GCC or another C99-capable compiler with GCC-compatible extensions.
- GNU make.
- ncurses development headers for `menuselect`.
- OpenSSL development headers.
- zlib development headers.
- pthread and standard C library development headers.

Useful optional dependencies:

- Sofia-SIP development files for `chan_sofia`.
- libopus development files for `codec_opus`.
- PostgreSQL development files for `res_config_pgsql` and related modules.
- ODBC, SQLite, Radius, DAHDI, Speex, GSM and other libraries depending on the
  modules you select.

`chan_sofia` currently expects Sofia-SIP headers and libraries in the standard
local Sofia-SIP install layout used by this tree:

```text
/usr/local/include/sofia-sip-1.13
/usr/local/lib
```

The linked library is:

```text
lsofia-sip-ua
```

If Sofia-SIP is installed in `/usr/local/lib`, make sure the dynamic linker can
find it:

```sh
ldconfig
```

## Full Build: chan_sofia + codec_opus

This is the complete build path for a GABPBX installation with both
`chan_sofia` and `codec_opus`.

### 1. Install system build packages

On Debian or Ubuntu, install the base compiler stack and common development
headers:

```sh
apt update
apt install build-essential pkg-config ncurses-dev libssl-dev zlib1g-dev libxml2-dev libsqlite3-dev libpq-dev unixodbc-dev
```

Install Opus headers and libraries:

```sh
apt install libopus-dev
```

Other modules may need additional libraries. `make menuselect` will show what
is available and what is missing.

### 2. Build and install Sofia-SIP

`chan_sofia` links against Sofia-SIP:

```text
lsofia-sip-ua
```

The current GABPBX make rules compile `chan_sofia` with:

```text
-I/usr/local/include/sofia-sip-1.13
-L/usr/local/lib -lsofia-sip-ua
```

That means Sofia-SIP must be installed in `/usr/local` for the default build.

If you build Sofia-SIP from source:

```sh
cd /path/to/sofia-sip
./configure --prefix=/usr/local
make
make install
ldconfig
```

Verify that the headers and library are visible:

```sh
test -d /usr/local/include/sofia-sip-1.13
test -f /usr/local/lib/libsofia-sip-ua.so || test -f /usr/local/lib/libsofia-sip-ua.a
pkg-config --libs opus
```

### 3. Configure GABPBX

From the GABPBX source directory:

```sh
./configure
```

This generates the local build configuration and dependency state used by
`make` and `menuselect`.

### 4. Select modules

Open the interactive selector:

```sh
make menuselect
```

Enable or verify these modules:

```text
Channel Drivers  -> chan_sofia
Codec Translators -> codec_opus
```

The modules can also be enabled non-interactively after `./configure` has
generated `menuselect.makeopts`:

```sh
menuselect/menuselect --enable chan_sofia menuselect.makeopts
menuselect/menuselect --enable codec_opus menuselect.makeopts
```

If dependencies are missing, `menuselect` or the build will report them. For
`chan_sofia`, check Sofia-SIP headers and `libsofia-sip-ua`. For `codec_opus`,
check `libopus-dev` and `pkg-config`.

### 5. Build and install

Use the normal build and install flow:

```sh
make
make install
```

For a configured tree, this is also valid and convenient:

```sh
make install
```

`make install` builds pending objects first, then installs the binaries and
modules.

For a first installation only, install sample configuration:

```sh
make samples
```

Be careful: `make samples` can overwrite existing configuration files under
`/etc/gabpbx`.

### 6. Configure modules.conf

`chan_sofia` is a drop-in replacement for `chan_sip`, so both must not be
loaded together.

Use:

```ini
noload => chan_sip.so
load => chan_sofia.so
load => codec_opus.so
```

### 7. Configure sofia.conf

Start from the provided sample:

```sh
install -m 644 configs/sofia.conf.sample /etc/gabpbx/sofia.conf
```

Minimal peer using Opus:

```ini
[general]
context=default
bindaddr=0.0.0.0
bindport=5060
allowguest=no
realm=gabpbx

[phone100]
type=peer
host=dynamic
secret=change-this-secret
context=internal
disallow=all
allow=opus
allow=alaw
allow=ulaw
dtmfmode=auto
nat=force_rport,comedia
directmedia=no
maxcontacts=3
call-limit=3
```

### 8. Configure codecs.conf for Opus

Start from the provided sample:

```sh
install -m 644 configs/codecs.conf.sample /etc/gabpbx/codecs.conf
```

Useful Opus defaults:

```ini
[opus]
bitrate => 32000
fec => true
dtx => false
```

### 9. Start and verify

Start in console mode:

```sh
gabpbx -vvvc
```

Or connect to a running instance:

```sh
gabpbx -r
```

Verify module loading:

```text
*CLI> module show like sofia
*CLI> module show like opus
*CLI> sip show settings
*CLI> sip show peers
*CLI> opus show
```

Expected results:

- `chan_sofia.so` is loaded.
- `codec_opus.so` is loaded.
- `sip show settings` reports the Sofia-SIP channel configuration.
- `opus show` reports bitrate, FEC, DTX and active encoder/decoder counts.

If `chan_sofia.so` does not load, check:

- `chan_sip.so` is not loaded.
- Sofia-SIP is installed in `/usr/local`.
- `/usr/local/lib` is visible to the dynamic linker.
- `ldconfig` has been run after installing Sofia-SIP.

If `codec_opus.so` does not build or load, check:

- `libopus-dev` is installed.
- `pkg-config --cflags opus` returns include flags.
- `pkg-config --libs opus` returns linker flags.

## Short Build Summary

Use the normal source build flow. Do not edit generated configure or make
scripts for a normal build.

```sh
./configure
make menuselect
make
make install
```

`make menuselect` is optional, but recommended. It lets you select modules and
see missing dependencies before the build.

For a configured tree, `make install` is also the normal deployment target: it
builds pending objects and then installs them.

For a first installation only, sample configuration files can be installed with:

```sh
make samples
```

Be careful: `make samples` can overwrite existing configuration files.

## Basic Runtime

Start GABPBX in foreground console mode:

```sh
gabpbx -vvvc
```

Connect to a running GABPBX instance:

```sh
gabpbx -r
```

Run a single CLI command:

```sh
gabpbx -rx "core show version"
gabpbx -rx "module show like sofia"
gabpbx -rx "sip show peers"
gabpbx -rx "opus show"
```

Load `chan_sofia` from the CLI:

```text
*CLI> module load chan_sofia.so
```

After changing SIP channel drivers, restart GABPBX instead of relying only on a
module reload, because `chan_sofia` and `chan_sip` own the same public SIP
names.

## Minimal chan_sofia Peer Example

```ini
[general]
context=default
bindaddr=0.0.0.0
bindport=5060
allowguest=no
realm=gabpbx

[phone100]
type=peer
host=dynamic
secret=change-this-secret
context=internal
disallow=all
allow=opus
allow=alaw
dtmfmode=auto
nat=force_rport,comedia
directmedia=no
maxcontacts=3
call-limit=3
```

Dialplan usage remains compatible with existing SIP dialplans:

```ini
exten => 100,1,Dial(SIP/phone100,30)
```

## Realtime Notes

`chan_sofia` uses the same `sippeers` realtime family as `chan_sip`.

Example `extconfig.conf` style:

```ini
sippeers => pgsql,general,sippeers
```

Registration state can also be separated into a `sipregs` realtime family when
configured. See:

```text
doc/realtime_sipregs.txt
doc/realtime_sippeers.txt
configs/res_pgsql.conf.sample
```

`res_config_pgsql` includes cache support and UDP cache invalidation support.
The sample configuration documents the available settings.

## Security Notes

- Do not expose SIP services to the public Internet without firewalling,
  strong secrets and abuse controls.
- Disable guest calls unless they are intentionally required.
- Use strong peer secrets.
- Keep system time synchronized with NTP; SIP registration and digest
  authentication are time-sensitive.
- Review `sofia.conf.sample` before deploying TLS, WS or WSS listeners.
- Do not load both `chan_sip.so` and `chan_sofia.so` at the same time.

## License

GABPBX is free software distributed under the terms of the GNU General Public
License Version 2. See `LICENSE` and `COPYING` in the source tree.

GABPBX preserves existing Asterisk, Digium and third-party notices where they
apply. New GABPBX work is maintained as part of the GABPBX project by Germán
Luis Aracil Boned <garacilb@gmail.com>.
