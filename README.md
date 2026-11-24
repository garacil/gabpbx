# GABPBX

GABPBX (Germán Aracil Boned PBX) is a GPLv2 open-source PBX and telephony toolkit, a fork of Asterisk first created in
2008, maintained by Germán Luis Aracil Boned <garacilb@gmail.com>.

Website: **<https://gabpbx.org/>** · en español: **<https://gabpbx.org/es/>** ·
[Releases](https://github.com/garacil/gabpbx/releases) · [Wiki](https://github.com/garacil/gabpbx/wiki) ·
[Changes](CHANGES)

## GABPBX 1.9.32 — the star is `chan_sofia`

GABPBX keeps the Asterisk architecture as it is: modules, the PBX core, the dialplan, the AMI and the realtime engines
(`extconfig.conf`, `sippeers`, `sipregs`). Its new work is in the SIP channel: **`chan_sofia`**, a SIP channel driver
built on the [Sofia-SIP](https://github.com/garacil/sofia-sip) stack that replaces `chan_sip`.

### Moving from `chan_sip`

```ini
; /etc/gabpbx/modules.conf
noload => chan_sip.so
load   => chan_sofia.so
```

The channel is still `SIP/<peer>`: dialplans, `sip show …`, the `SIPpeers` / `SIPshowpeer` AMI actions, the
`sippeers` realtime family and the `SIPPEER` / `SIP_HEADER` functions keep working. Load one driver or the other, not
both. Details: [Migrating from chan_sip](https://github.com/garacil/gabpbx/wiki/Migrating-from-chan_sip).

### What `chan_sofia` does

- **SIP:** registrar and outbound registration, PRACK, UPDATE, session timers, REFER transfers, MESSAGE, presence and
  BLF, MWI, PUBLISH, GRUU, Path, Service-Route, SIP Outbound, Diversion and call forwarding set on the phone.
- **WebRTC:** SIP over WS and WSS, DTLS-SRTP, ICE-lite, rtcp-mux and BUNDLE; two-way audio and video and relayed
  DataChannels; no `pjproject` and no `libnice`.
- **Media:** RTP/RTCP, SRTP (SDES and DTLS), Opus and `.opus` files, T.38 fax, direct media, every DTMF mode.
- **Transports:** UDP, TCP, TLS, WS and WSS, each with its own address and port.
- **Security:** MD5 and SHA-256 digest, a nonce good for one request, a request enters only from an address of its
  account or with its digest, calls go only to declared peers, a local blacklist, TLS hardening.
- **Operations:** the `chan_sip` CLI and AMI, realtime peers, and every SIP message, decrypted, sent to a HEP
  collector.
- **Scale:** one Sofia event thread plus a small I/O pool, XXH3 hash tables, a bounded pool for realtime
  registration writes.

The whole list is on the wiki: [Features](https://github.com/garacil/gabpbx/wiki/Features),
[chan_sofia](https://github.com/garacil/gabpbx/wiki/Chan-Sofia), [WebRTC](https://github.com/garacil/gabpbx/wiki/WebRTC)
and [Security](https://github.com/garacil/gabpbx/wiki/Security) (with the standard each check follows).

## Binary packages

Every release ships amd64 packages on its [GitHub release page](https://github.com/garacil/gabpbx/releases), with
`SHA256SUMS`:

- `.deb` for Debian 12 and 13 and Ubuntu 22.04 and 24.04: `apt install ./gabpbx_…deb`
- `.rpm` for RHEL 9 and its rebuilds: `dnf install epel-release && dnf install ./gabpbx-…rpm`

Each one is built and tested in its own distribution and carries its own build of Sofia-SIP. `modules.conf` loads
`chan_sofia` and not `chan_sip`; `gabpbx.service` is installed but not enabled.

## Building from source

The usual Asterisk workflow (`./configure && make && make install`), plus what `chan_sofia` needs:

- **Sofia-SIP 2.1.1**, built from source into `/usr/local` **before** GABPBX (it is not the distribution's package):
  tag `v2.1.1` of [garacil/sofia-sip](https://github.com/garacil/sofia-sip);
- `libssl-dev`, `libsrtp2-dev`, `libopus-dev`, `libogg-dev`; optional: `libusrsctp-dev` (WebRTC DataChannels),
  `libpq-dev` (PostgreSQL realtime and CDR);
- the Asterisk ones: `build-essential pkg-config libedit-dev libjansson-dev libxml2-dev libsqlite3-dev uuid-dev
  libncurses-dev zlib1g-dev`.

```sh
# 1) Sofia-SIP into /usr/local
git clone https://github.com/garacil/sofia-sip.git && cd sofia-sip
git checkout v2.1.1
./autogen.sh
./configure --prefix=/usr/local && make && sudo make install && sudo ldconfig

# 2) GABPBX
cd /path/to/gabpbx
./configure
make menuselect.makeopts
make -j$(nproc)
sudo make install
```

Step by step, per distribution, with the dependency of each module and troubleshooting:
[Build and Installation](https://github.com/garacil/gabpbx/wiki/Build-and-Installation).

## License

GABPBX is distributed under the GNU General Public License v2 (GPLv2). Existing Asterisk, Digium and third-party
copyright notices and license terms are preserved in the source files where they apply.

— Germán Luis Aracil Boned
