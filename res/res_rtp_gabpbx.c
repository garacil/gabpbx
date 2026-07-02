/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * GABPBX as a project is based on Asterisk.
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 *
 * Existing copyright, authorship, Asterisk/Digium notices,
 * third-party notices, and GPL licensing terms are preserved when present.
 *
 * Copyright (C) 1999 - 2008, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.gabpbx.org for more information about
 * the GABPBX project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*!
 * \file
 *
 * \brief Supports RTP and RTCP with Symmetric RTP support for NAT traversal.
 *
 * \author Mark Spencer <markster@digium.com>
 *
 * \note RTP is defined in RFC 3550.
 *
 * \ingroup rtp_engines
 */

/*** MODULEINFO
	<use>openssl</use>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 366880 $")

#include <sys/time.h>
#include <signal.h>
#include <fcntl.h>

#include "gabpbx/stun.h"
#include "gabpbx/pbx.h"
#include "gabpbx/frame.h"
#include "gabpbx/channel.h"
#include "gabpbx/acl.h"
#include "gabpbx/config.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/cli.h"
#include "gabpbx/manager.h"
#include "gabpbx/unaligned.h"
#include "gabpbx/module.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/sched.h"		/* ast_sched_thread_* — dedicated DTLS retransmit scheduler (WebRTC Fix B) */

/* WebRTC A2: DTLS-SRTP (optional, compiled out when OpenSSL is absent — MODULEINFO <use>openssl</use>). */
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/srtp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#endif

#define MAX_TIMESTAMP_SKEW	640

#define RTP_SEQ_MOD     (1<<16)	/*!< A sequence number can't be more than 16 bits */
#define RTCP_DEFAULT_INTERVALMS   5000	/*!< Default milli-seconds between RTCP reports we send */
#define RTCP_MIN_INTERVALMS       500	/*!< Min milli-seconds between RTCP reports we send */
#define RTCP_MAX_INTERVALMS       60000	/*!< Max milli-seconds between RTCP reports we send */

#define DEFAULT_RTP_START 5000 /*!< Default port number to start allocating RTP ports from */
#define DEFAULT_RTP_END 31000  /*!< Default maximum port number to end allocating RTP ports at */

#define MINIMUM_RTP_PORT 1024 /*!< Minimum port number to accept */
#define MAXIMUM_RTP_PORT 65535 /*!< Maximum port number to accept */

#define RTCP_PT_FUR     192
#define RTCP_PT_SR      200
#define RTCP_PT_RR      201
#define RTCP_PT_SDES    202
#define RTCP_PT_BYE     203
#define RTCP_PT_APP     204

#define RTP_MTU		1200

#define DEFAULT_DTMF_TIMEOUT (150 * (8000 / 1000))	/*!< samples */

#define ZFONE_PROFILE_ID 0x505a

#define DEFAULT_LEARNING_MIN_SEQUENTIAL 4

extern struct ast_srtp_res *res_srtp;
extern struct ast_srtp_policy_res *res_srtp_policy;	/* WebRTC A2: SRTP policy backend (for DTLS key install) */
static int dtmftimeout = DEFAULT_DTMF_TIMEOUT;

static int rtpstart = DEFAULT_RTP_START;			/*!< First port for RTP sessions (set in rtp.conf) */
static int rtpend = DEFAULT_RTP_END;			/*!< Last port for RTP sessions (set in rtp.conf) */
static int rtpdebug;			/*!< Are we debugging? */
static int rtpicedebug;			/*!< WebRTC ICE/DTLS debug ("rtp set debug ice on"): pure logging, default OFF, ZERO datapath change */
static int rtcpdebug;			/*!< Are we debugging RTCP? */
static int rtcpstats;			/*!< Are we debugging RTCP? */
static int rtcpinterval = RTCP_DEFAULT_INTERVALMS; /*!< Time between rtcp reports in millisecs */
static struct ast_sockaddr rtpdebugaddr;	/*!< Debug packets to/from this host */
static struct ast_sockaddr rtcpdebugaddr;	/*!< Debug RTCP packets to/from this host */
static int rtpdebugport;		/*< Debug only RTP packets from IP or IP+Port if port is > 0 */
static int rtcpdebugport;		/*< Debug only RTCP packets from IP or IP+Port if port is > 0 */
#ifdef SO_NO_CHECK
static int nochecksums;
#endif
static int strictrtp;			/*< Only accept RTP frames from a defined source. If we receive an indication of a changing source, enter learning mode. */
static int learning_min_sequential;	/*< Number of sequential RTP frames needed from a single source during learning mode to accept new source. */

enum strict_rtp_state {
	STRICT_RTP_OPEN = 0, /*! No RTP packets should be dropped, all sources accepted */
	STRICT_RTP_LEARN,    /*! Accept next packet as source */
	STRICT_RTP_CLOSED,   /*! Drop all RTP packets not coming from source that was learned */
};

#define FLAG_3389_WARNING               (1 << 0)
#define FLAG_NAT_ACTIVE                 (3 << 1)
#define FLAG_NAT_INACTIVE               (0 << 1)
#define FLAG_NAT_INACTIVE_NOWARN        (1 << 1)
#define FLAG_NEED_MARKER_BIT            (1 << 3)
#define FLAG_DTMF_COMPENSATE            (1 << 4)

/*! \brief RTP session description */
#ifdef HAVE_OPENSSL
/*! \brief WebRTC A2: per-instance DTLS-SRTP association state (rtcp-mux: one per ast_rtp). */
struct dtls_details {
	SSL_CTX *ssl_ctx;             /*!< per-instance SSL context (cert/key/cipher/SRTP profile) */
	SSL *ssl;                     /*!< per-association SSL object */
	BIO *read_bio;                /*!< BIO_s_mem fed with inbound DTLS records (SSL reads here) */
	BIO *write_bio;               /*!< custom BIO over rtp->s, drains outbound records to the wire */
	enum ast_rtp_dtls_setup dtls_setup;      /*!< OUR a=setup role */
	enum ast_rtp_dtls_connection connection; /*!< NEW / EXISTING */
	int timeout_timer;            /*!< DTLSv1 retransmit sched id (-1 = none) */
};
#endif

struct ast_rtp {
	int s;
	struct ast_frame f;
	unsigned char rawdata[8192 + AST_FRIENDLY_OFFSET];
	unsigned int ssrc;		/*!< Synchronization source, RFC 3550, page 10. */
	unsigned int themssrc;		/*!< Their SSRC */
	unsigned int rxssrc;
	/* WebRTC BUNDLE (RFC 8843; gated by AST_RTP_PROPERTY_BUNDLE / rtp->bundle). When set, this single
	 * instance/transport carries BOTH audio and a video sub-stream, demultiplexed by payload type. The video
	 * sub-stream keeps its OWN SSRC/seqno/cycle/count state so its RTP is well-formed (a single SSRC must not
	 * mix payload types from different bundled m-sections, RFC 8843) and so a 2nd SSRC never triggers the audio
	 * SRCCHANGE. All of these are zero/unused unless rtp->bundle == 1 (then non-WebRTC stays byte-identical). */
	unsigned int bundle:1;          /*!< 1 = audio+video on this transport (set via AST_RTP_PROPERTY_BUNDLE) */
	unsigned int v_ssrc;            /*!< TX SSRC of the bundled video sub-stream (distinct from audio ssrc) */
	unsigned short v_seqno;         /*!< TX sequence number of the bundled video sub-stream */
	unsigned int v_lastts;          /*!< TX RTP timestamp clock of the bundled video sub-stream (audio keeps rtp->lastts) */
	unsigned int v_rxssrc;          /*!< Last RX SSRC of the video sub-stream */
	int v_lastrxseqno;              /*!< Last RX sequence number of the video sub-stream */
	unsigned short v_seedrxseqno;   /*!< First RX sequence number of the video sub-stream */
	unsigned int v_rxcount;         /*!< RX packet count of the video sub-stream */
	unsigned int v_cycles;          /*!< Shifted seqno-cycle count of the video sub-stream */
	/* WebRTC BUNDLE MID RTP header extension (RFC 8843 §9 MUST / RFC 8285): when mid_ext_id > 0 we stamp the
	 * one-byte MID header extension (sdes:mid) on every egressing bundled RTP packet so a strict max-bundle
	 * browser associates the SSRC with the correct m= line. audio -> mid_value_audio, video -> mid_value_video. */
	int mid_ext_id;                 /*!< negotiated RFC 8285 extmap id for sdes:mid (0 = disabled/non-WebRTC) */
	char mid_value_audio[17];       /*!< a=mid of the audio m= line stamped in RTP; the RFC 8285 one-byte extension caps a mid at 16 bytes (+NUL) so the stamped value always equals the a=mid we signalled (e.g. Firefox "sdparta_0"). "0" for Chrome/Safari. */
	char mid_value_video[17];       /*!< a=mid of the bundled video m= line (RFC 8285 one-byte ext: <=16 bytes + NUL) */
	unsigned int lastts;
	unsigned int lastrxts;
	unsigned int lastividtimestamp;
	unsigned int lastovidtimestamp;
	unsigned int lastitexttimestamp;
	unsigned int lastotexttimestamp;
	unsigned int lasteventseqn;
	int lastrxseqno;                /*!< Last received sequence number */
	int lostrtp;
	unsigned short seedrxseqno;     /*!< What sequence number did they start with?*/
	unsigned int seedrxts;          /*!< What RTP timestamp did they start with? */
	unsigned int rxcount;           /*!< How many packets have we received? */
	unsigned int rxoctetcount;      /*!< How many octets have we received? should be rxcount *160*/
	unsigned int txcount;           /*!< How many packets have we sent? */
	unsigned int txoctetcount;      /*!< How many octets have we sent? (txcount*160)*/
	unsigned int cycles;            /*!< Shifted count of sequence number cycles */
	double rxjitter;                /*!< Interarrival jitter at the moment in seconds */
	double rxtransit;               /*!< Relative transit time for previous packet */
	format_t lasttxformat;
	format_t lastrxformat;

	int rtptimeout;			/*!< RTP timeout time (negative or zero means disabled, negative value means temporarily disabled) */
	int rtpholdtimeout;		/*!< RTP timeout when on hold (negative or zero means disabled, negative value means temporarily disabled). */
	int rtpkeepalive;		/*!< Send RTP comfort noice packets for keepalive */

	/* DTMF Reception Variables */
	char resp;
	unsigned int lastevent;
	unsigned int dtmf_duration;     /*!< Total duration in samples since the digit start event */
	unsigned int dtmf_timeout;      /*!< When this timestamp is reached we consider END frame lost and forcibly abort digit */
	unsigned int dtmfsamples;
	enum ast_rtp_dtmf_mode dtmfmode;/*!< The current DTMF mode of the RTP stream */
	/* DTMF Transmission Variables */
	unsigned int lastdigitts;
	char sending_digit;	/*!< boolean - are we sending digits */
	char send_digit;	/*!< digit we are sending */
	int send_payload;
	int send_duration;
	unsigned int flags;
	struct timeval rxcore;
	struct timeval txcore;
	double drxcore;                 /*!< The double representation of the first received packet */
	struct timeval lastrx;          /*!< timeval when we last received a packet */
	struct timeval dtmfmute;
	struct ast_smoother *smoother;
	int *ioid;
	unsigned short seqno;		/*!< Sequence number, RFC 3550, page 13. */
	unsigned short rxseqno;
	struct sched_context *sched;
	struct io_context *io;
	void *data;
	struct ast_rtcp *rtcp;
	struct ast_rtp *bridged;        /*!< Who we are Packet bridged to */

	enum strict_rtp_state strict_rtp_state; /*!< Current state that strict RTP protection is in */
	struct ast_sockaddr strict_rtp_address;  /*!< Remote address information for strict RTP purposes */
	struct ast_sockaddr alt_rtp_address; /*!<Alternate remote address information */

	/*
	 * Learning mode values based on pjmedia's probation mode.  Many of these values are redundant to the above,
	 * but these are in place to keep learning mode sequence values sealed from their normal counterparts.
	 */
	uint16_t learning_max_seq;		/*!< Highest sequence number heard */
	int learning_probation;		/*!< Sequential packets untill source is valid */

#ifdef HAVE_OPENSSL
	struct dtls_details dtls;          /*!< WebRTC A2: RTP DTLS association (rtcp-mux: the only one) */
	enum ast_rtp_dtls_hash remote_hash;                /*!< hash from the remote a=fingerprint */
	unsigned char remote_fingerprint[EVP_MAX_MD_SIZE]; /*!< parsed binary remote fingerprint */
	unsigned int remote_fingerprint_len;               /*!< its length (0 = none stored; C2 fail-closed) */
	char local_fingerprint[160];       /*!< OUR cert fingerprint (colon-hex) for SDP a=fingerprint */
	enum ast_srtp_suite suite;         /*!< negotiated SRTP suite (set from the DTLS-selected profile) */
	struct ast_rtp_dtls_cfg dtls_cfg;  /*!< copy of cfg from set_configuration */
	unsigned int dtls_failure:1;       /*!< handshake/fingerprint failed -> tear the call down */
	int rekeyid;                       /*!< rekey sched id (-1 = none) */
	/* WebRTC A3: ICE-lite state (RFC 8445 §2.5) — we are permanently the controlled, lite agent.
	 * Touched on the channel/sofia thread (set_authentication/get_* during SDP) AND the RTP read path
	 * (the STUN responder); all serialised by ao2_lock(instance): the A1 wrappers lock the engine
	 * callbacks and the demux responder takes the SAME lock (like the DTLS branch). ao2 locks ARE
	 * recursive (PTHREAD_MUTEX_RECURSIVE_NP, main/lock.c:88-91) so the responder's re-lock is safe. */
	char local_ufrag[12];              /*!< OUR ice-ufrag (>=4, RFC 8445 §5.4); CSPRNG-generated */
	char local_pwd[28];                /*!< OUR ice-pwd = HMAC key (>=22); CSPRNG-generated */
	char remote_ufrag[257];            /*!< browser's ice-ufrag (<=256 + NUL); prefix-matched */
	char remote_pwd[257];              /*!< browser's ice-pwd (<=256 + NUL); stored for symmetry */
	struct ast_sockaddr ice_peer;      /*!< validated peer addr learned from the first good check */
	enum ast_rtp_ice_role ice_role;    /*!< always AST_RTP_ICE_ROLE_CONTROLLED for a lite agent */
	unsigned int ice_lite:1;           /*!< peer advertised a=ice-lite (recorded only) */
	unsigned int ice_active:1;         /*!< start() called — the responder is armed (hardening: gate) */
	unsigned int ice_complete:1;       /*!< a USE-CANDIDATE check passed → selected pair (RFC 8445 §8.2) */
	/* rtpicedebug ONLY (pure logging, no datapath): first-seen bits + last-* sockaddrs so the debug
	 * logs fire once / on-change instead of per-packet. Never read outside an `if (rtpicedebug)` guard. */
	unsigned int latch_seen:1;         /*!< rtpicedebug: first ICE latch already logged */
	unsigned int rx_seen:1;            /*!< rtpicedebug: first post-complete media packet already logged */
	unsigned int dtls_drop_seen:1;     /*!< rtpicedebug: first DTLS-record source!=ice_peer drop already logged */
	unsigned int srtp_rx_logged:1;     /*!< rtpicedebug: first successful SRTP decrypt already logged (B3) */
	unsigned int srtp_auth_fail;       /*!< rtpicedebug: running count of SRTP unprotect failures (B3, wrong key / replay / forgery) */
	struct ast_sockaddr last_latch;    /*!< rtpicedebug: last latched source (log latch source CHANGES only) */
	struct ast_sockaddr last_media;    /*!< rtpicedebug: last media source (log media source CHANGES only) */
	struct ast_sockaddr last_dtls_drop;/*!< rtpicedebug: last dropped DTLS-record source (log CHANGES only) */
#endif
	struct rtp_red *red;
};

/*!
 * \brief Structure defining an RTCP session.
 *
 * The concept "RTCP session" is not defined in RFC 3550, but since
 * this structure is analogous to ast_rtp, which tracks a RTP session,
 * it is logical to think of this as a RTCP session.
 *
 * RTCP packet is defined on page 9 of RFC 3550.
 *
 */
struct ast_rtcp {
	int rtcp_info;
	int s;				/*!< Socket */
	struct ast_sockaddr us;		/*!< Socket representation of the local endpoint. */
	struct ast_sockaddr them;	/*!< Socket representation of the remote endpoint. */
	unsigned int soc;		/*!< What they told us */
	unsigned int spc;		/*!< What they told us */
	unsigned int themrxlsr;		/*!< The middle 32 bits of the NTP timestamp in the last received SR*/
	struct timeval rxlsr;		/*!< Time when we got their last SR */
	struct timeval txlsr;		/*!< Time when we sent or last SR*/
	unsigned int expected_prior;	/*!< no. packets in previous interval */
	unsigned int received_prior;	/*!< no. packets received in previous interval */
	int schedid;			/*!< Schedid returned from ast_sched_add() to schedule RTCP-transmissions*/
	unsigned int rr_count;		/*!< number of RRs we've sent, not including report blocks in SR's */
	unsigned int sr_count;		/*!< number of SRs we've sent */
	unsigned int lastsrtxcount;     /*!< Transmit packet count when last SR sent */
	double accumulated_transit;	/*!< accumulated a-dlsr-lsr */
	double rtt;			/*!< Last reported rtt */
	unsigned int reported_jitter;	/*!< The contents of their last jitter entry in the RR */
	unsigned int reported_lost;	/*!< Reported lost packets in their RR */

	double reported_maxjitter;
	double reported_minjitter;
	double reported_normdev_jitter;
	double reported_stdev_jitter;
	unsigned int reported_jitter_count;

	double reported_maxlost;
	double reported_minlost;
	double reported_normdev_lost;
	double reported_stdev_lost;

	double rxlost;
	double maxrxlost;
	double minrxlost;
	double normdev_rxlost;
	double stdev_rxlost;
	unsigned int rxlost_count;

	double maxrxjitter;
	double minrxjitter;
	double normdev_rxjitter;
	double stdev_rxjitter;
	unsigned int rxjitter_count;
	double maxrtt;
	double minrtt;
	double normdevrtt;
	double stdevrtt;
	unsigned int rtt_count;
};

struct rtp_red {
	struct ast_frame t140;  /*!< Primary data  */
	struct ast_frame t140red;   /*!< Redundant t140*/
	/* MAX_GENERATION + 1 entries: rtp_red_init writes the PRIMARY pt at index `generations`, and
	 * red_t140_to_red writes len[num_gen] (num_gen == generations), so the valid index range is
	 * 0..generations inclusive. Sizing to MAX only was a latent OOB when generations == MAX. */
	unsigned char pt[AST_RED_MAX_GENERATION + 1];  /*!< Payload types for redundancy data (+ primary at [generations]) */
	unsigned char ts[AST_RED_MAX_GENERATION + 1]; /*!< Time stamps */
	unsigned short len[AST_RED_MAX_GENERATION + 1]; /*!< length of each generation (RFC 2198 10-bit block length) */
	int num_gen; /*!< Number of generations */
	int schedid; /*!< Timer id */
	int ti; /*!< How long to buffer data before send */
	unsigned char t140red_data[64000];
	unsigned char buf_data[64000]; /*!< buffered primary data */
	int hdrlen;
	long int prev_ts;
};

AST_LIST_HEAD_NOLOCK(frame_list, ast_frame);

/* Forward Declarations */
static int ast_rtp_new(struct ast_rtp_instance *instance, struct sched_context *sched, struct ast_sockaddr *addr, void *data);
static int ast_rtp_destroy(struct ast_rtp_instance *instance);
static int ast_rtp_dtmf_begin(struct ast_rtp_instance *instance, char digit);
static int ast_rtp_dtmf_end(struct ast_rtp_instance *instance, char digit);
static int ast_rtp_dtmf_end_with_duration(struct ast_rtp_instance *instance, char digit, unsigned int duration);
static int ast_rtp_dtmf_mode_set(struct ast_rtp_instance *instance, enum ast_rtp_dtmf_mode dtmf_mode);
static enum ast_rtp_dtmf_mode ast_rtp_dtmf_mode_get(struct ast_rtp_instance *instance);
static void ast_rtp_update_source(struct ast_rtp_instance *instance);
static void ast_rtp_change_source(struct ast_rtp_instance *instance);
static int ast_rtp_write(struct ast_rtp_instance *instance, struct ast_frame *frame);
static struct ast_frame *ast_rtp_read(struct ast_rtp_instance *instance, int rtcp);
/* WebRTC FIX 1: parse one already-unprotected RTCP datagram (shared by ast_rtcp_read + the rtcp-mux demux). */
static struct ast_frame *ast_rtcp_interpret(struct ast_rtp_instance *instance, unsigned int *rtcpheader, int res, struct ast_sockaddr *addrp);
static void ast_rtp_prop_set(struct ast_rtp_instance *instance, enum ast_rtp_property property, int value);
static int ast_rtp_fd(struct ast_rtp_instance *instance, int rtcp);
static void ast_rtp_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr);
static void ast_rtp_alt_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr);
static int rtp_red_init(struct ast_rtp_instance *instance, int buffer_time, int *payloads, int generations);
static int rtp_red_buffer(struct ast_rtp_instance *instance, struct ast_frame *frame);
static int ast_rtp_local_bridge(struct ast_rtp_instance *instance0, struct ast_rtp_instance *instance1);
static int ast_rtp_get_stat(struct ast_rtp_instance *instance, struct ast_rtp_instance_stats *stats, enum ast_rtp_instance_stat stat);
static int ast_rtp_dtmf_compatible(struct ast_channel *chan0, struct ast_rtp_instance *instance0, struct ast_channel *chan1, struct ast_rtp_instance *instance1);
static void ast_rtp_stun_request(struct ast_rtp_instance *instance, struct ast_sockaddr *suggestion, const char *username);
static void ast_rtp_stop(struct ast_rtp_instance *instance);
static int ast_rtp_qos_set(struct ast_rtp_instance *instance, int tos, int cos, const char* desc);
static int ast_rtp_sendcng(struct ast_rtp_instance *instance, int level);

#ifdef HAVE_OPENSSL
/*
 * WebRTC A2: DTLS-SRTP engine vtable. Called UNLOCKED by contract — the A1 wrapper vtable in
 * main/rtp_engine.c already ao2_locks every dispatch, so locking here would double-lock needlessly.
 * (The ao2 instance lock IS recursive — PTHREAD_MUTEX_RECURSIVE_NP, main/lock.c:88-91 — so a re-lock
 * would not deadlock; A3's responder deliberately re-locks. The earlier "not recursive" note here was
 * wrong; the A2 code is unaffected as it never re-enters.)
 */
/* WebRTC A2: DTLS-SRTP self-signed certs cannot chain-verify (RFC 5763 §5) — the SDP a=fingerprint is
 * the sole trust anchor, enforced fail-closed by the post-handshake memcmp (step 6). This callback only
 * lets the handshake capture the peer cert; it asserts NO chain validity (it is NOT verification). */
static int gabpbx_dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	return 1;
}

/* Generate an ephemeral EC P-256 keypair (the WebRTC norm; trust is via the SDP fingerprint, Q4). */
static int gabpbx_dtls_ephemeral_keypair(EVP_PKEY **keypair)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	*keypair = EVP_EC_gen(SN_X9_62_prime256v1);
	return *keypair ? 0 : -1;
#else
	EC_KEY *eckey;
	EC_GROUP *group;

	if (!(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))) {
		return -1;
	}
	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
	if (!(eckey = EC_KEY_new()) || !EC_KEY_set_group(eckey, group) || !EC_KEY_generate_key(eckey)
		|| !(*keypair = EVP_PKEY_new())) {
		EC_KEY_free(eckey);
		EC_GROUP_free(group);
		return -1;
	}
	if (!EVP_PKEY_assign_EC_KEY(*keypair, eckey)) {
		EC_KEY_free(eckey);
		EVP_PKEY_free(*keypair);
		*keypair = NULL;
		EC_GROUP_free(group);
		return -1;
	}
	EC_GROUP_free(group);
	return 0;
#endif
}

/* Build a self-signed X509 around the keypair (CN=gabpbx, SHA-256, notBefore-1d / notAfter+30d). */
static int gabpbx_dtls_ephemeral_cert(EVP_PKEY *keypair, X509 **certificate)
{
	X509 *cert;
	BIGNUM *serial;
	X509_NAME *name;

	if (!(cert = X509_new())) {
		return -1;
	}
	X509_set_version(cert, 2);
	X509_set_pubkey(cert, keypair);

	if (!(serial = BN_new())) {
		X509_free(cert);
		return -1;
	}
	BN_rand(serial, 159, -1, 0);
	BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(cert));
	BN_free(serial);

	X509_time_adj_ex(X509_getm_notBefore(cert), -1, 0, NULL);
	X509_time_adj_ex(X509_getm_notAfter(cert), 30, 0, NULL);

	name = X509_get_subject_name(cert);
	X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char *) "gabpbx", -1, -1, 0);
	X509_set_issuer_name(cert, name);

	if (!X509_sign(cert, keypair, EVP_sha256())) {
		X509_free(cert);
		return -1;
	}
	*certificate = cert;
	return 0;
}

/* Load cert+key from configured PEM files (non-ephemeral path). */
static int gabpbx_dtls_cert_from_file(const struct ast_rtp_dtls_cfg *cfg, EVP_PKEY **pkey, X509 **cert)
{
	FILE *fp;
	BIO *certbio;
	const char *keyfile = ast_strlen_zero(cfg->pvtfile) ? cfg->certfile : cfg->pvtfile;

	*pkey = NULL;
	*cert = NULL;
	if (!(fp = fopen(keyfile, "r"))) {
		return -1;
	}
	if (!PEM_read_PrivateKey(fp, pkey, NULL, NULL)) {
		fclose(fp);
		return -1;
	}
	fclose(fp);

	if (!(certbio = BIO_new(BIO_s_file()))) {
		EVP_PKEY_free(*pkey);
		*pkey = NULL;
		return -1;
	}
	if (!BIO_read_filename(certbio, cfg->certfile) || !(*cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
		BIO_free_all(certbio);
		EVP_PKEY_free(*pkey);
		*pkey = NULL;
		return -1;
	}
	BIO_free_all(certbio);
	return 0;
}

/* Dispatch: ephemeral (Q4 default — when ephemeral_cert is set or no certfile) or configured files. */
static int gabpbx_dtls_load_cert(const struct ast_rtp_dtls_cfg *cfg, EVP_PKEY **pkey, X509 **cert)
{
	if (cfg->ephemeral_cert || ast_strlen_zero(cfg->certfile)) {
		if (gabpbx_dtls_ephemeral_keypair(pkey)) {
			return -1;
		}
		if (gabpbx_dtls_ephemeral_cert(*pkey, cert)) {
			EVP_PKEY_free(*pkey);
			*pkey = NULL;
			return -1;
		}
		return 0;
	}
	return gabpbx_dtls_cert_from_file(cfg, pkey, cert);
}

/* Free the instance-owned deep copy of the DTLS config (C5). */
static void gabpbx_dtls_cfg_free(struct ast_rtp_dtls_cfg *cfg)
{
	ast_free(cfg->certfile);
	ast_free(cfg->pvtfile);
	ast_free(cfg->cipher);
	ast_free(cfg->cafile);
	ast_free(cfg->capath);
	cfg->certfile = cfg->pvtfile = cfg->cipher = cfg->cafile = cfg->capath = NULL;
}

/* Deep-copy the caller's DTLS config into instance-owned storage (C5; ast_strdup(NULL)==NULL). */
static int gabpbx_dtls_cfg_copy(struct ast_rtp_dtls_cfg *dst, const struct ast_rtp_dtls_cfg *src)
{
	gabpbx_dtls_cfg_free(dst);
	*dst = *src;
	dst->certfile = ast_strdup(src->certfile);
	dst->pvtfile  = ast_strdup(src->pvtfile);
	dst->cipher   = ast_strdup(src->cipher);
	dst->cafile   = ast_strdup(src->cafile);
	dst->capath   = ast_strdup(src->capath);
	/* ast_strdup(NULL) returns NULL legitimately; flag only when a non-NULL source failed to copy. */
	if ((src->certfile && !dst->certfile) || (src->pvtfile && !dst->pvtfile)
		|| (src->cipher && !dst->cipher) || (src->cafile && !dst->cafile)
		|| (src->capath && !dst->capath)) {
		return -1;
	}
	return 0;
}

/* Keep DTLS handshake flights under the typical WebRTC path MTU. */
#define GABPBX_DTLS_MTU 1200

/* File-static DTLS write-BIO method, created in load_module / freed in unload_module. */
static BIO_METHOD *dtls_bio_methods;

/* Dedicated scheduler thread for DTLS handshake retransmit timers (WebRTC). The RTP instance's
 * rtp->sched is the BORROWED sofia_sched context — arming a timer on it via ast_sched_add_variable does
 * NOT wake that sleeping thread (only ast_sched_thread_add_variable signals the cond), so a lost DTLS
 * flight is retransmitted late or never → ~1/3 no-audio intermittency. This module-private thread is
 * woken on every add. Created in load_module, destroyed in unload_module. */
static struct ast_sched_thread *dtls_sched_thread;

/* WebRTC A2: raw datagram send bypassing res_srtp->protect — DTLS records (and the A3 STUN responder)
 * go on the wire in the clear. */
static int rtp_raw_sendto(struct ast_rtp *rtp, void *data, int len, struct ast_sockaddr *sa, int rtcp)
{
	return ast_sendto(rtcp ? rtp->rtcp->s : rtp->s, data, len, 0, sa);
}

static int dtls_bio_new(BIO *bio)
{
	BIO_set_init(bio, 1);
	BIO_set_data(bio, NULL);
	BIO_set_shutdown(bio, 0);
	return 1;
}

static int dtls_bio_free(BIO *bio)
{
	/* The ast_rtp_instance* carried in the BIO data is NOT refcounted — its lifetime is the
	 * instance's and it is touched only by the instance's own threads. */
	BIO_set_data(bio, NULL);
	return 1;
}

static int dtls_bio_write(BIO *bio, const char *buf, int len)
{
	struct ast_rtp_instance *instance = BIO_get_data(bio);
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote = { {0,} };

	ast_rtp_instance_get_remote_address(instance, &remote);
	if (ast_sockaddr_isnull(&remote)) {
		return len;	/* nowhere to send yet; the DTLSv1 retransmit timer resends the flight */
	}
	rtp_raw_sendto(rtp, (void *) buf, len, &remote, 0);	/* rtcp-mux: always rtp->s */
	return len;	/* always claim success — OpenSSL cannot tolerate a short/failed datagram send */
}

static long dtls_bio_ctrl(BIO *bio, int cmd, long arg1, void *arg2)
{
	switch (cmd) {
	case BIO_CTRL_FLUSH:
		return 1;
	case BIO_CTRL_DGRAM_QUERY_MTU:
		return GABPBX_DTLS_MTU;
	case BIO_CTRL_WPENDING:
	case BIO_CTRL_PENDING:
		return 0L;
	default:
		return 0;
	}
}

/* Build the per-association SSL object: the mem read-BIO the recv path feeds + the custom write-BIO,
 * then arm accept/connect per our role. SSL_free later frees both attached BIOs. */
static int dtls_details_initialize(struct ast_rtp *rtp, struct ast_rtp_instance *instance)
{
	struct dtls_details *dtls = &rtp->dtls;

	if (!(dtls->ssl = SSL_new(dtls->ssl_ctx))) {
		ast_log(LOG_ERROR, "Failed to create SSL object for RTP instance '%p'\n", instance);
		return -1;
	}
	if (!(dtls->read_bio = BIO_new(BIO_s_mem()))) {
		SSL_free(dtls->ssl);
		dtls->ssl = NULL;
		return -1;
	}
	BIO_set_mem_eof_return(dtls->read_bio, -1);	/* never signal EOF on the mem read BIO */
	if (!(dtls->write_bio = BIO_new(dtls_bio_methods))) {
		BIO_free(dtls->read_bio);
		dtls->read_bio = NULL;
		SSL_free(dtls->ssl);
		dtls->ssl = NULL;
		return -1;
	}
	BIO_set_data(dtls->write_bio, instance);
	SSL_set_bio(dtls->ssl, dtls->read_bio, dtls->write_bio);

	if (dtls->dtls_setup == AST_RTP_DTLS_SETUP_PASSIVE) {
		SSL_set_accept_state(dtls->ssl);	/* we wait for the ClientHello */
	} else {
		SSL_set_connect_state(dtls->ssl);	/* active/actpass: we initiate */
	}
	dtls->connection = AST_RTP_DTLS_CONNECTION_NEW;
	return 0;
}

/* Free the DTLS association objects (SSL_free also frees its attached read/write BIOs). The retransmit
 * timer must already be stopped by the caller. */
static void dtls_free_association(struct ast_rtp *rtp)
{
	if (rtp->dtls.ssl) {
		SSL_free(rtp->dtls.ssl);
		rtp->dtls.ssl = NULL;
		rtp->dtls.read_bio = NULL;
		rtp->dtls.write_bio = NULL;
	}
	if (rtp->dtls.ssl_ctx) {
		SSL_CTX_free(rtp->dtls.ssl_ctx);
		rtp->dtls.ssl_ctx = NULL;
	}
	gabpbx_dtls_cfg_free(&rtp->dtls_cfg);
}

static int dtls_srtp_handle_timeout(const void *data);

/* Arm the DTLSv1 retransmit timer for the flight just sent (no-op if already armed). ao2_ref(+1)
 * before sched, mirroring the canonical pattern at res_rtp_gabpbx.c:2323. PRECONDITION: instance locked. */
static void dtls_srtp_start_timeout_timer(struct ast_rtp_instance *instance, struct ast_rtp *rtp)
{
	struct timeval tv = { 0, };
	int timeout_ms;

	/* Fail closed if the dedicated DTLS scheduler is unavailable (load_module create failed). Arming on the
	 * borrowed rtp->sched (sofia_sched) context via ast_sched_add_variable would NOT wake that sleeping
	 * thread, so the retransmit fires late/never → no-audio; we use the module-private waking thread instead.
	 * set_configuration already refuses DTLS when this is NULL, so this is belt only. */
	if (!dtls_sched_thread) {
		ast_log(LOG_ERROR, "DTLS retransmit timer: no DTLS scheduler — failing the handshake (instance '%p')\n", instance);
		rtp->dtls_failure = 1;
		return;
	}

	if (rtp->dtls.timeout_timer > -1 || !rtp->dtls.ssl || !DTLSv1_get_timeout(rtp->dtls.ssl, &tv)) {
		return;
	}
	timeout_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	if (timeout_ms <= 0) {
		timeout_ms = 1;	/* never schedule at 0 — a single sched thread serves all RTP */
	}
	ao2_ref(instance, +1);
	/* variable=1: each reschedule uses the callback's returned next timeout (the DTLSv1 backoff).
	 * ast_sched_add (== variable=0) IGNORES the callback return and reuses the fixed initial interval,
	 * defeating DTLS's exponential retransmit backoff. Mirrors Asterisk res_rtp_asterisk's dtls timer.
	 * NOTE: a stop that loses the race with a mid-flight callback can let it reschedule ONCE more after
	 * the stop; that is benign — the retained instance ref keeps it alive and the next fire self-stops
	 * (ssl==NULL after free, or DTLSv1_get_timeout==0) and drops the ref. */
	if ((rtp->dtls.timeout_timer = ast_sched_thread_add_variable(dtls_sched_thread, timeout_ms, dtls_srtp_handle_timeout, instance, 1)) < 0) {
		ao2_ref(instance, -1);
	}
}

/* sched-thread callback: retransmit the timed-out handshake flight and reschedule. */
static int dtls_srtp_handle_timeout(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance *) data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct timeval tv = { 0, };
	int next_ms;

	ao2_lock(instance);
	if (!rtp->dtls.ssl) {
		rtp->dtls.timeout_timer = -1;
		ao2_unlock(instance);
		ao2_ref(instance, -1);
		return 0;
	}
	DTLSv1_handle_timeout(rtp->dtls.ssl);	/* retransmits the lost flight */
	if (!DTLSv1_get_timeout(rtp->dtls.ssl, &tv)) {
		rtp->dtls.timeout_timer = -1;
		ao2_unlock(instance);
		ao2_ref(instance, -1);	/* not rescheduled — drop the sched ref */
		return 0;
	}
	next_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	if (next_ms <= 0) {
		next_ms = 1;	/* never 0 — a single sched thread serves all RTP */
	}
	ao2_unlock(instance);
	return next_ms;	/* >0 reschedules; the ao2 ref is retained while armed */
}

/* Stop the retransmit timer. PRECONDITION: instance NOT locked (deadlocks against the locked callback).
 * Mirrors the file's RTCP teardown idiom (ast_rtcp_write self-unrefs on its stop path, :2047):
 * AST_SCHED_DEL retries until the entry is actually gone, and we drop the ref ONLY when it removed a
 * still-pending entry (returns 0). If the callback is mid-flight (del fails), the callback owns the
 * drop on its own return-0 path — so exactly one ao2 unref happens. (AST_SCHED_DEL_UNREF would
 * unconditionally drop whenever id>-1 after the retry loop, double-dropping with the self-unref
 * callback = an instance UAF.) */
static void dtls_srtp_stop_timeout_timer(struct ast_rtp_instance *instance, struct ast_rtp *rtp)
{
	/* Crash belt: never delete on a NULL scheduler (or no armed timer). The DTLS timer lives on the
	 * module-private dtls_sched_thread (not the borrowed rtp->sched). ast_sched_thread_del wraps the same
	 * AST_SCHED_DEL retry idiom and returns 0 only when it removed a still-pending entry — drop the ref
	 * ONLY then (a mid-flight callback owns its own drop; an unconditional drop would double-unref = UAF). */
	if (!dtls_sched_thread || rtp->dtls.timeout_timer < 0) {
		return;
	}
	if (ast_sched_thread_del(dtls_sched_thread, rtp->dtls.timeout_timer) == 0) {
		ao2_ref(instance, -1);
	}
}

static int gabpbx_dtls_set_configuration(struct ast_rtp_instance *instance, const struct ast_rtp_dtls_cfg *dtls_cfg)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	const EVP_MD *md;
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	unsigned int size, i;
	char *p;

	if (!dtls_cfg->enabled) {
		return 0;
	}

	/* Fail closed: a DTLS association needs the dedicated DTLS scheduler for the handshake retransmit
	 * timer (dtls_srtp_start_timeout_timer -> ast_sched_thread_add_variable(dtls_sched_thread,...)). If
	 * load_module could not create it, REFUSE to configure DTLS so the caller (chan_sofia A4/A5 commit)
	 * rejects the SDP — never build a DTLS association whose retransmit timer could never fire. */
	if (!dtls_sched_thread) {
		ast_log(LOG_ERROR, "Cannot configure DTLS on RTP instance '%p': no DTLS scheduler\n", instance);
		return -1;
	}

	/* C5: own a deep copy of the config (the char* paths) for the instance lifetime. */
	if (gabpbx_dtls_cfg_copy(&rtp->dtls_cfg, dtls_cfg)) {
		ast_log(LOG_ERROR, "Failed to copy DTLS configuration for RTP instance '%p'\n", instance);
		return -1;
	}

	/* (Re)build the per-instance DTLS context. Tear down any prior association first (call-once from
	 * the SDP glue in practice, but be safe on reconfiguration — free the SSL before its ssl_ctx). */
	rtp->dtls_failure = 0;	/* a fresh handshake starts clean (HIGH2/LOW7) */
	if (rtp->dtls.timeout_timer > -1) {
		/* MED4: cancel the old retransmit timer so the new handshake arms fresh and the stale sched id
		 * is released. set_configuration runs LOCKED (A1 wrapper); the stop precondition is
		 * instance-NOT-locked, so unlock/stop/relock. */
		ao2_unlock(instance);
		dtls_srtp_stop_timeout_timer(instance, rtp);
		ao2_lock(instance);
	}
	if (rtp->dtls.ssl) {
		SSL_free(rtp->dtls.ssl);
		rtp->dtls.ssl = NULL;
		rtp->dtls.read_bio = NULL;
		rtp->dtls.write_bio = NULL;
	}
	if (rtp->dtls.ssl_ctx) {
		SSL_CTX_free(rtp->dtls.ssl_ctx);
		rtp->dtls.ssl_ctx = NULL;
	}
	if (!(rtp->dtls.ssl_ctx = SSL_CTX_new(DTLS_method()))) {
		ast_log(LOG_ERROR, "Failed to create DTLS context for RTP instance '%p'\n", instance);
		return -1;
	}
	SSL_CTX_set_read_ahead(rtp->dtls.ssl_ctx, 1);

	/* C3: self-signed WebRTC certs — request the peer cert (so we can fingerprint it) but accept it at
	 * the chain layer; the fail-closed a=fingerprint memcmp (step 6) is the trust. Full chain checking
	 * only when AST_RTP_DTLS_VERIFY_CERTIFICATE is explicitly configured. */
	SSL_CTX_set_verify(rtp->dtls.ssl_ctx,
		(rtp->dtls_cfg.verify & (AST_RTP_DTLS_VERIFY_FINGERPRINT | AST_RTP_DTLS_VERIFY_CERTIFICATE))
			? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_NONE,
		(rtp->dtls_cfg.verify & AST_RTP_DTLS_VERIFY_CERTIFICATE) ? NULL : gabpbx_dtls_verify_callback);

	/* Load the CA store only when full certificate-chain verification is requested; fail closed if the
	 * configured trust path is unusable. */
	if ((rtp->dtls_cfg.verify & AST_RTP_DTLS_VERIFY_CERTIFICATE)
		&& (!ast_strlen_zero(rtp->dtls_cfg.cafile) || !ast_strlen_zero(rtp->dtls_cfg.capath))
		&& !SSL_CTX_load_verify_locations(rtp->dtls.ssl_ctx,
			ast_strlen_zero(rtp->dtls_cfg.cafile) ? NULL : rtp->dtls_cfg.cafile,
			ast_strlen_zero(rtp->dtls_cfg.capath) ? NULL : rtp->dtls_cfg.capath)) {
		ast_log(LOG_ERROR, "Failed to load the DTLS CA trust store for RTP instance '%p'\n", instance);
		return -1;
	}

#ifndef OPENSSL_NO_SRTP
	/* O3: offer both profiles; the negotiated one is read back via SSL_get_selected_srtp_profile and
	 * installed at step 6 (do NOT pre-commit to cfg->suite). C4: guarded by OPENSSL_NO_SRTP. */
	if (SSL_CTX_set_tlsext_use_srtp(rtp->dtls.ssl_ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")) {
		ast_log(LOG_ERROR, "Failed to set SRTP profiles on DTLS context for RTP instance '%p'\n", instance);
		return -1;
	}
#else
	ast_log(LOG_ERROR, "OpenSSL was built without SRTP support; DTLS-SRTP is unavailable\n");
	return -1;
#endif

	if (!ast_strlen_zero(rtp->dtls_cfg.cipher)
		&& !SSL_CTX_set_cipher_list(rtp->dtls.ssl_ctx, rtp->dtls_cfg.cipher)) {
		ast_log(LOG_ERROR, "Invalid DTLS cipher list '%s' for RTP instance '%p'\n",
			rtp->dtls_cfg.cipher, instance);
		return -1;
	}

	/* Obtain the certificate/key (ephemeral by default, Q4) and install into the context. */
	if (gabpbx_dtls_load_cert(&rtp->dtls_cfg, &pkey, &cert)) {
		ast_log(LOG_ERROR, "Failed to obtain a DTLS certificate for RTP instance '%p'\n", instance);
		return -1;
	}
	if (!SSL_CTX_use_certificate(rtp->dtls.ssl_ctx, cert)
		|| !SSL_CTX_use_PrivateKey(rtp->dtls.ssl_ctx, pkey)
		|| !SSL_CTX_check_private_key(rtp->dtls.ssl_ctx)) {
		ast_log(LOG_ERROR, "Failed to install DTLS certificate/key for RTP instance '%p'\n", instance);
		X509_free(cert);
		EVP_PKEY_free(pkey);
		return -1;
	}

	/* Compute OUR fingerprint (colon-hex) for the SDP a=fingerprint line. */
	md = (rtp->dtls_cfg.hash == AST_RTP_DTLS_HASH_SHA1) ? EVP_sha1() : EVP_sha256();
	if (!X509_digest(cert, md, fingerprint, &size) || !size) {
		ast_log(LOG_ERROR, "Failed to compute the DTLS fingerprint for RTP instance '%p'\n", instance);
		X509_free(cert);
		EVP_PKEY_free(pkey);
		return -1;
	}
	p = rtp->local_fingerprint;
	for (i = 0; i < size; i++) {
		sprintf(p, "%02hhX:", fingerprint[i]);
		p += 3;
	}
	*(p - 1) = '\0';	/* strip the trailing ':' */

	/* The context holds its own refs now (SSL_CTX_use_* up-ref). */
	X509_free(cert);
	EVP_PKEY_free(pkey);

	rtp->dtls.dtls_setup = rtp->dtls_cfg.default_setup;
	rtp->suite = rtp->dtls_cfg.suite;	/* provisional; replaced by the DTLS-negotiated suite at step 6 */

	/* Build the per-association SSL object + read/write BIOs. */
	if (dtls_details_initialize(rtp, instance)) {
		return -1;
	}

	return 0;
}

static int gabpbx_dtls_active(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->dtls.ssl != NULL;
}

static void gabpbx_dtls_stop(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* Vtable callback — runs LOCKED (the A1 wrapper takes ao2_lock). Stop the retransmit timer with the
	 * lock briefly dropped (its precondition is instance-NOT-locked — it deadlocks against the locked
	 * sched callback), then free the association. */
	if (rtp->dtls.timeout_timer > -1) {
		ao2_unlock(instance);
		dtls_srtp_stop_timeout_timer(instance, rtp);
		ao2_lock(instance);
	}
	dtls_free_association(rtp);
}

static void gabpbx_dtls_reset(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (!rtp->dtls.ssl) {
		return;
	}
	rtp->dtls_failure = 0;
	SSL_clear(rtp->dtls.ssl);
	if (rtp->dtls.dtls_setup == AST_RTP_DTLS_SETUP_PASSIVE) {
		SSL_set_accept_state(rtp->dtls.ssl);
	} else {
		SSL_set_connect_state(rtp->dtls.ssl);
	}
	rtp->dtls.connection = AST_RTP_DTLS_CONNECTION_NEW;
}

static enum ast_rtp_dtls_connection gabpbx_dtls_get_connection(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->dtls.connection;
}

static enum ast_rtp_dtls_setup gabpbx_dtls_get_setup(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->dtls.dtls_setup;
}

static void gabpbx_dtls_set_setup(struct ast_rtp_instance *instance, enum ast_rtp_dtls_setup setup)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	enum ast_rtp_dtls_setup old_setup = rtp->dtls.dtls_setup;

	/* Map the REMOTE a=setup to OUR role (RFC 5763 §5). On a remote ACTPASS offer the answerer MAY pick
	 * either role; we pick PASSIVE (RFC 5763 §5 SHOULD) so the BROWSER is the DTLS client and INITIATES the
	 * handshake — the browser's native, reliable path. (gabpbx-active was intermittent: wire-confirmed the
	 * browser stayed silent as the DTLS server, never answering our retransmitted ClientHello → no SRTP → no
	 * audio.) Only the WebRTC ANSWERER passes actpass here; the offerer's answer-parse passes
	 * the browser's concrete active/passive. */
	switch (setup) {
	case AST_RTP_DTLS_SETUP_ACTIVE:
		rtp->dtls.dtls_setup = AST_RTP_DTLS_SETUP_PASSIVE;	/* remote active -> we passive */
		break;
	case AST_RTP_DTLS_SETUP_PASSIVE:
		rtp->dtls.dtls_setup = AST_RTP_DTLS_SETUP_ACTIVE;	/* remote passive -> we active */
		break;
	case AST_RTP_DTLS_SETUP_ACTPASS:
		rtp->dtls.dtls_setup = AST_RTP_DTLS_SETUP_PASSIVE;	/* remote actpass -> we PASSIVE (browser = DTLS client, it initiates) */
		break;
	case AST_RTP_DTLS_SETUP_HOLDCONN:
		rtp->dtls.dtls_setup = AST_RTP_DTLS_SETUP_HOLDCONN;
		return;	/* do not touch SSL state */
	}

	if (rtp->dtls.ssl && rtp->dtls.dtls_setup != old_setup) {
		if (rtp->dtls.dtls_setup == AST_RTP_DTLS_SETUP_PASSIVE) {
			SSL_set_accept_state(rtp->dtls.ssl);
		} else {
			SSL_set_connect_state(rtp->dtls.ssl);
		}
	}
}

static void gabpbx_dtls_set_fingerprint(struct ast_rtp_instance *instance, enum ast_rtp_dtls_hash hash, const char *fingerprint)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	const char *p = fingerprint;
	unsigned int n = 0;

	rtp->remote_hash = hash;
	if (!fingerprint) {
		rtp->remote_fingerprint_len = 0;
		return;
	}
	/* Parse the colon-hex "AB:CD:.." remote fingerprint into binary for the step-6 memcmp. Require a
	 * full hex pair before consuming two chars (p[1]==NUL is not xdigit) so a malformed/odd-length
	 * fingerprint can never advance past the NUL terminator (LOW9 out-of-bounds read). */
	while (*p && n < sizeof(rtp->remote_fingerprint)) {
		if (*p == ':') {
			p++;
			continue;
		}
		if (!isxdigit((unsigned char) p[0]) || !isxdigit((unsigned char) p[1])
			|| sscanf(p, "%02hhx", &rtp->remote_fingerprint[n]) != 1) {
			break;
		}
		n++;
		p += 2;
	}
	rtp->remote_fingerprint_len = n;
}

static enum ast_rtp_dtls_hash gabpbx_dtls_get_fingerprint_hash(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->dtls_cfg.hash;
}

static const char *gabpbx_dtls_get_fingerprint(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->local_fingerprint;
}

/* WebRTC DataChannel (Phase 1). Encrypt and send application data out over the established DTLS
 * association. SSL_write hands the record to the write BIO (dtls_bio_write -> rtp_raw_sendto), so it
 * rides the same datagram socket as DTLS-SRTP (BUNDLE). Runs LOCKED — invoked via the A1 wrapper which
 * holds ao2_lock(instance); we re-lock (recursive) to mirror the locking discipline of this file. */
static int gabpbx_dtls_write_appdata(struct ast_rtp_instance *instance, const void *buf, size_t len)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct dtls_details *dtls = &rtp->dtls;
	int res;

	ao2_lock(instance);
	if (!dtls->ssl || !SSL_is_init_finished(dtls->ssl)) {
		ao2_unlock(instance);
		return -1;	/* no established DTLS association to write over */
	}
	res = SSL_write(dtls->ssl, buf, len);
	ao2_unlock(instance);

	return res <= 0 ? -1 : res;
}

static struct ast_rtp_engine_dtls gabpbx_dtls = {
	.set_configuration    = gabpbx_dtls_set_configuration,
	.active               = gabpbx_dtls_active,
	.stop                 = gabpbx_dtls_stop,
	.reset                = gabpbx_dtls_reset,
	.get_connection       = gabpbx_dtls_get_connection,
	.get_setup            = gabpbx_dtls_get_setup,
	.set_setup            = gabpbx_dtls_set_setup,
	.set_fingerprint      = gabpbx_dtls_set_fingerprint,
	.get_fingerprint_hash = gabpbx_dtls_get_fingerprint_hash,
	.get_fingerprint      = gabpbx_dtls_get_fingerprint,
	.write_appdata        = gabpbx_dtls_write_appdata,
};

/* SRTP master key/salt lengths for the AES_CM_128 suites (the only DTLS-SRTP profiles A2 offers). */
#define DTLS_SRTP_MASTER_KEY_LEN  16
#define DTLS_SRTP_MASTER_SALT_LEN 14
#define DTLS_SRTP_KEY_SALT_LEN    (DTLS_SRTP_MASTER_KEY_LEN + DTLS_SRTP_MASTER_SALT_LEN)	/* 30 */

/* Build one SRTP policy from a contiguous [16-byte key || 14-byte salt] buffer — mirrors the SDES
 * set_crypto_policy (sdp_crypto.c): same res_srtp seam, key sourced from the DTLS exporter. */
static int dtls_set_srtp_policy(struct ast_srtp_policy *policy, enum ast_srtp_suite suite,
	const unsigned char *key_salt, unsigned long ssrc, int inbound)
{
	if (res_srtp_policy->set_master_key(policy, key_salt, DTLS_SRTP_MASTER_KEY_LEN,
			key_salt + DTLS_SRTP_MASTER_KEY_LEN, DTLS_SRTP_MASTER_SALT_LEN) < 0) {
		return -1;
	}
	if (res_srtp_policy->set_suite(policy, suite)) {
		return -1;
	}
	res_srtp_policy->set_ssrc(policy, ssrc, inbound);
	return 0;
}

/* Install the inbound + outbound SRTP policies on the instance (Q2: self-contained in res, mirroring
 * sdp_crypto_activate including the T39 RTCP-before-get_stats workaround for the libsrtp-2.x
 * single-wildcard restriction). Keys come from the DTLS exporter, not a=crypto. */
static int dtls_install_srtp(struct ast_rtp_instance *instance, struct ast_rtp *rtp,
	const unsigned char *local_key_salt, const unsigned char *remote_key_salt)
{
	struct ast_srtp_policy *local_policy, *remote_policy;
	struct ast_rtp_instance_stats stats = { 0, };
	int res = -1;

	if (!ast_rtp_engine_srtp_is_registered()) {
		return -1;
	}
	if (!(local_policy = res_srtp_policy->alloc())) {
		return -1;
	}
	if (!(remote_policy = res_srtp_policy->alloc())) {
		res_srtp_policy->destroy(local_policy);
		return -1;
	}
	/* T39: enable RTCP before get_stats so LOCAL_SSRC is real -> the outbound policy is ssrc_specific
	 * (libsrtp 2.x allows only ONE wildcard policy per session). */
	ast_rtp_instance_set_prop(instance, AST_RTP_PROPERTY_RTCP, 1);
	if (ast_rtp_instance_get_stats(instance, &stats, AST_RTP_INSTANCE_STAT_LOCAL_SSRC)) {
		stats.local_ssrc = 0;
	}
	if (dtls_set_srtp_policy(local_policy, rtp->suite, local_key_salt, stats.local_ssrc, 0)
		|| dtls_set_srtp_policy(remote_policy, rtp->suite, remote_key_salt, 0, 1)) {
		goto done;
	}
	if (ast_rtp_instance_add_srtp_policy(instance, remote_policy, local_policy)) {
		ast_log(LOG_WARNING, "Could not install DTLS-SRTP policies for RTP instance '%p'\n", instance);
		goto done;
	}
	/* WebRTC BUNDLE: the bundled video sub-stream egresses on a SECOND local SSRC (rtp->v_ssrc). The policies
	 * above cover only the audio SSRC (ssrc_specific outbound) plus the remote inbound wildcard, so without this
	 * libsrtp has NO outbound context for v_ssrc -> res_srtp->protect() fails -> the video packet is dropped
	 * before ast_sendto() -> the browser never receives video (chrome://webrtc-internals shows NO inbound-rtp
	 * video). Add a SECOND specific outbound policy for v_ssrc (specific, not a wildcard, so the libsrtp-2.x
	 * single-wildcard limit is respected). Mirrors Asterisk's multi-local-SSRC model. */
	if (rtp->bundle && rtp->v_ssrc) {	/* only a BUNDLE leg muxes video on v_ssrc; gate on rtp->bundle so a knob-OFF leg installs no extra SRTP stream (byte-identical) */
		struct ast_srtp_policy *video_policy = res_srtp_policy->alloc();
		if (video_policy) {
			if (!dtls_set_srtp_policy(video_policy, rtp->suite, local_key_salt, rtp->v_ssrc, 0)
					&& ast_rtp_instance_add_srtp_stream(instance, video_policy)) {
				ast_log(LOG_WARNING, "Could not add bundled-video SRTP stream (v_ssrc %u) for RTP instance '%p'\n",
					rtp->v_ssrc, instance);
			}
			res_srtp_policy->destroy(video_policy);
		}
	}
	res = 0;
done:
	res_srtp_policy->destroy(local_policy);
	res_srtp_policy->destroy(remote_policy);
	return res;
}

/* On handshake completion: verify the peer fingerprint (C2/C3, fail-closed), read the negotiated SRTP
 * profile (O3), export the keying material, split by role, and install. Runs LOCKED (called from
 * handle_record under the demux lock); briefly drops the lock only to stop the retransmit timer. */
static void dtls_srtp_finish_negotiation(struct ast_rtp_instance *instance, struct ast_rtp *rtp)
{
	struct dtls_details *dtls = &rtp->dtls;
	X509 *cert;
	unsigned char material[DTLS_SRTP_KEY_SALT_LEN * 2];	/* client + server: 60 bytes */
	unsigned char local_ks[DTLS_SRTP_KEY_SALT_LEN], remote_ks[DTLS_SRTP_KEY_SALT_LEN];
	const unsigned char *local_key, *remote_key, *local_salt, *remote_salt;
#ifndef OPENSSL_NO_SRTP
	SRTP_PROTECTION_PROFILE *prof;
#endif

	/* Stop the retransmit timer (precondition instance-NOT-locked) — unlock/relock around it. */
	if (dtls->timeout_timer > -1) {
		ao2_unlock(instance);
		dtls_srtp_stop_timeout_timer(instance, rtp);
		ao2_lock(instance);
	}

	/* C2/C3: the SDP a=fingerprint is the trust anchor — fail closed. */
	if (!(cert = SSL_get_peer_certificate(dtls->ssl))) {
		ast_log(LOG_WARNING, "DTLS peer presented no certificate for RTP instance '%p'\n", instance);
		rtp->dtls_failure = 1;
		return;
	}
	/* Fail CLOSED, UNCONDITIONALLY: for DTLS-SRTP the SDP a=fingerprint is the SOLE trust anchor for
	 * the peer's (typically self-signed) cert (RFC 8827 §6.5, RFC 5763 §5), so the comparison MUST run
	 * on every DTLS-SRTP session regardless of the verify bitmask. The earlier gate
	 * `(verify & (FINGERPRINT|CERTIFICATE)) || remote_fingerprint_len` still skipped the check when
	 * verify == AST_RTP_DTLS_VERIFY_NONE (rtp_engine.h:412) AND no fingerprint was stored, installing
	 * SRTP keys against an UNVERIFIED peer (latent fail-OPEN). All chan_sofia callers set
	 * verify=FINGERPRINT and store a remote fingerprint, so the working WebRTC handshake is unchanged. */
	{
		unsigned char fp[EVP_MAX_MD_SIZE];
		unsigned int n;
		const EVP_MD *md = (rtp->remote_hash == AST_RTP_DTLS_HASH_SHA1) ? EVP_sha1() : EVP_sha256();

		if (!rtp->remote_fingerprint_len) {
			ast_log(LOG_WARNING, "DTLS-SRTP refused: no remote a=fingerprint stored for RTP instance '%p' — refusing to key an unverified peer\n", instance);
			X509_free(cert);
			rtp->dtls_failure = 1;
			return;
		}
		if (!X509_digest(cert, md, fp, &n) || n != rtp->remote_fingerprint_len
			|| memcmp(fp, rtp->remote_fingerprint, n) != 0) {
			ast_log(LOG_WARNING, "DTLS fingerprint mismatch for RTP instance '%p' — possible MITM, rejecting\n", instance);
			X509_free(cert);
			rtp->dtls_failure = 1;
			return;
		}
	}
	X509_free(cert);

#ifndef OPENSSL_NO_SRTP
	/* O3: install the DTLS-negotiated suite, not cfg->suite. */
	if (!(prof = SSL_get_selected_srtp_profile(dtls->ssl))) {
		ast_log(LOG_WARNING, "No SRTP profile negotiated for RTP instance '%p'\n", instance);
		rtp->dtls_failure = 1;
		return;
	}
	if (prof->id == SRTP_AES128_CM_SHA1_80) {
		rtp->suite = AST_AES_CM_128_HMAC_SHA1_80;
	} else if (prof->id == SRTP_AES128_CM_SHA1_32) {
		rtp->suite = AST_AES_CM_128_HMAC_SHA1_32;
	} else {
		ast_log(LOG_WARNING, "Unsupported SRTP profile %lu for RTP instance '%p'\n", (unsigned long) prof->id, instance);
		rtp->dtls_failure = 1;
		return;
	}
#endif

	/* RFC 5764 keying-material export. */
	if (!SSL_export_keying_material(dtls->ssl, material, sizeof(material),
			"EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
		ast_log(LOG_WARNING, "DTLS key export failed for RTP instance '%p'\n", instance);
		rtp->dtls_failure = 1;
		return;
	}

	/* Exporter layout: client_key | server_key | client_salt | server_salt. We are client when ACTIVE.
	 * local = what WE encrypt with (outbound); remote = what THEY encrypt with (inbound). */
	if (dtls->dtls_setup == AST_RTP_DTLS_SETUP_ACTIVE) {
		local_key   = material;
		remote_key  = material + DTLS_SRTP_MASTER_KEY_LEN;
		local_salt  = material + DTLS_SRTP_MASTER_KEY_LEN * 2;
		remote_salt = material + DTLS_SRTP_MASTER_KEY_LEN * 2 + DTLS_SRTP_MASTER_SALT_LEN;
	} else {
		remote_key  = material;
		local_key   = material + DTLS_SRTP_MASTER_KEY_LEN;
		remote_salt = material + DTLS_SRTP_MASTER_KEY_LEN * 2;
		local_salt  = material + DTLS_SRTP_MASTER_KEY_LEN * 2 + DTLS_SRTP_MASTER_SALT_LEN;
	}
	memcpy(local_ks, local_key, DTLS_SRTP_MASTER_KEY_LEN);
	memcpy(local_ks + DTLS_SRTP_MASTER_KEY_LEN, local_salt, DTLS_SRTP_MASTER_SALT_LEN);
	memcpy(remote_ks, remote_key, DTLS_SRTP_MASTER_KEY_LEN);
	memcpy(remote_ks + DTLS_SRTP_MASTER_KEY_LEN, remote_salt, DTLS_SRTP_MASTER_SALT_LEN);

	if (dtls_install_srtp(instance, rtp, local_ks, remote_ks)) {
		rtp->dtls_failure = 1;
		return;
	}
	dtls->connection = AST_RTP_DTLS_CONNECTION_EXISTING;
	if (rtpicedebug) {	/* B2: the key DTLS/SRTP ordering milestone — handshake done, SRTP keys installed (no keys logged) */
		char *p_peer = ast_strdupa(ast_sockaddr_stringify(&rtp->ice_peer));
		ast_verbose("ICE-DTLS established inst=%p rtp=%p setup=%d ice_peer=%s (SRTP installed)\n",
			instance, rtp, (int)dtls->dtls_setup, p_peer);
	}
	ast_debug(1, "DTLS-SRTP negotiated and installed for RTP instance '%p'\n", instance);
}

/* Feed an inbound DTLS record to OpenSSL and pump the handshake. Runs LOCKED — the demux holds
 * ao2_lock(instance). The record is always consumed (returns 0). Step 5 arms the retransmit timer;
 * step 6 detects completion, verifies the a=fingerprint, and installs the SRTP keys. */
static int dtls_srtp_handle_record(struct ast_rtp_instance *instance, struct ast_rtp *rtp, char *buf, int len)
{
	struct dtls_details *dtls = &rtp->dtls;
	char rxbuf[8192];
	int res;

	if (!dtls->ssl) {
		return 0;
	}
	/* An inbound DTLS record at an ACTPASS offerer (provision_offer, before the answer fixes our role)
	 * means the peer (browser answering a=setup:active) is the DTLS client: commit us to the SERVER role
	 * NOW so SSL processes the ClientHello as the server (RFC 5763 §5 — an actpass offerer MUST be ready to
	 * receive a ClientHello before the answer arrives). Companion to the early provision_offer ice->start.
	 * Mirrors Asterisk 22 res_rtp_asterisk.c. */
	if (dtls->dtls_setup == AST_RTP_DTLS_SETUP_ACTPASS) {
		dtls->dtls_setup = AST_RTP_DTLS_SETUP_PASSIVE;
		SSL_set_accept_state(dtls->ssl);
		if (rtpicedebug) {	/* B2: inbound ClientHello arrived on an actpass offerer -> we commit to DTLS server */
			ast_verbose("ICE-DTLS role ACTPASS->PASSIVE inst=%p rtp=%p (inbound ClientHello: we are the DTLS server)\n",
				instance, rtp);
		}
	}
	BIO_write(dtls->read_bio, buf, len);

	if (!SSL_is_init_finished(dtls->ssl)) {
		res = SSL_do_handshake(dtls->ssl);	/* drives the next flight out via the write BIO */
		if (res <= 0) {
			int err = SSL_get_error(dtls->ssl, res);
			if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_NONE) {
				ast_log(LOG_WARNING, "DTLS handshake error %d for RTP instance '%p'\n", err, instance);
				rtp->dtls_failure = 1;
				/* Stop any already-armed retransmit timer (unlock/stop/relock — handle_record runs
				 * LOCKED) so a fatal failure does not leave it firing. */
				if (rtp->dtls.timeout_timer > -1) {
					ao2_unlock(instance);
					dtls_srtp_stop_timeout_timer(instance, rtp);
					ao2_lock(instance);
				}
				return -1;	/* fatal — fail the read so the call is torn down */
			}
		}
		if (SSL_is_init_finished(dtls->ssl)) {
			dtls_srtp_finish_negotiation(instance, rtp);	/* verify fingerprint + export keys + install SRTP */
		} else {
			dtls_srtp_start_timeout_timer(instance, rtp);	/* still handshaking — keep the retransmit timer armed */
		}
		/* finish_negotiation may fail closed (fingerprint mismatch / export / install) — propagate it. */
		return rtp->dtls_failure ? -1 : 0;
	}

	/* Handshake finished — drain any DTLS application data and hand each chunk to a registered
	 * consumer (WebRTC DataChannel, Phase 1). ast_rtp_instance_dtls_deliver_appdata is a no-op
	 * returning 0 when no consumer is registered, so with no datachannel the behaviour is unchanged:
	 * drain the records and drop them (none expected on plain media). Runs LOCKED. */
	while ((res = SSL_read(dtls->ssl, rxbuf, sizeof(rxbuf))) > 0) {
		ast_rtp_instance_dtls_deliver_appdata(instance, (uint8_t *) rxbuf, res);
	}
	/* res <= 0: SSL_ERROR_WANT_READ is the normal "no more data" exit; any other error is benign here
	 * (handshake completion/teardown is handled above and by the demux). */
	return rtp->dtls_failure ? -1 : 0;
}

/* Fire the active-side DTLS handshake (sends ClientHello via the write BIO). The passive side starts
 * on the inbound ClientHello in the demux. O2: locked around the initiation. Initiate ONLY when the role
 * is concretely ACTIVE — never while still ACTPASS: with the offerer's STUN responder now armed early
 * (provision_offer ice->start), a USE-CANDIDATE can call this before the answer fixes our role, and an
 * actpass offerer MUST NOT send a ClientHello (RFC 5763 §5 — it waits to receive the peer's; the inbound
 * record handler commits us to PASSIVE). When the answer makes us ACTIVE (peer answered passive), the
 * post-answer activate fires this. Mirrors Asterisk 22. */
static void dtls_perform_handshake(struct ast_rtp_instance *instance, struct ast_rtp *rtp)
{
	ao2_lock(instance);
	if (rtp->dtls.ssl && rtp->dtls.dtls_setup == AST_RTP_DTLS_SETUP_ACTIVE) {
		SSL_do_handshake(rtp->dtls.ssl);
		dtls_srtp_start_timeout_timer(instance, rtp);	/* arm the retransmit timer for the ClientHello */
		if (rtpicedebug) {	/* B2: active-side ClientHello sent */
			ast_verbose("ICE-DTLS handshake-fired inst=%p rtp=%p (active side, ClientHello sent)\n", instance, rtp);
		}
	} else if (rtpicedebug) {	/* B2: not fired (passive side waits for the ClientHello, or no ssl yet) */
		ast_verbose("ICE-DTLS handshake-skip inst=%p rtp=%p ssl=%d setup=%d\n",
			instance, rtp, rtp->dtls.ssl ? 1 : 0, (int)rtp->dtls.dtls_setup);
	}
	ao2_unlock(instance);
}
#endif /* HAVE_OPENSSL */

static int ast_rtp_activate(struct ast_rtp_instance *instance)
{
#ifdef HAVE_OPENSSL
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* WebRTC A2/A3: kick the active-side DTLS handshake once the transport is ready. With ICE in play
	 * (A3), defer until ICE has validated the peer so the ClientHello has a destination; without ICE
	 * (plain A2 / non-WebRTC DTLS) fire immediately (ice_active stays 0 → condition true). */
	if (rtp->dtls.ssl && (!rtp->ice_active || rtp->ice_complete)) {
		dtls_perform_handshake(instance, rtp);
	}
#endif
	return 0;
}

#ifdef HAVE_OPENSSL
/* ===== WebRTC A3: ICE-lite (RFC 8445 §2.5) — minimal STUN responder agent, no pjproject =====
 * The 9 engine callbacks below run UNLOCKED — the A1 wrapper vtable (main/rtp_engine.c) holds
 * ao2_lock(instance) around every dispatch. */

/* Fill dst with ICE-chars (RFC 8445 §5.4) from a CSPRNG (RAND_bytes; the pwd is the HMAC key, so it
 * must be unpredictable — NOT ast_random()). The 64-char set divides 256 evenly, so no modulo bias. */
static int ice_rand_string(char *dst, size_t len)
{
	static const char set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned char raw[64];
	size_t i, n = (len > 0) ? len - 1 : 0;

	if (n > sizeof(raw)) {
		n = sizeof(raw);
	}
	if (n && RAND_bytes(raw, (int) n) != 1) {
		dst[0] = '\0';
		return -1;	/* CSPRNG failure → the caller MUST fail closed (empty creds = publicly-known key) */
	}
	for (i = 0; i < n; i++) {
		dst[i] = set[raw[i] % (sizeof(set) - 1)];
	}
	dst[i] = '\0';
	return 0;
}

/* ao2 helpers for the single-HOST-candidate container returned by get_local_candidates. */
static int ice_cand_hash(const void *obj, int flags) { return 0; }
static int ice_cand_cmp(void *o, void *arg, int flags) { return CMP_MATCH | CMP_STOP; }
static void ice_cand_dtor(void *obj)
{
	struct ast_rtp_engine_ice_candidate *c = obj;
	ast_free(c->foundation);
	ast_free(c->transport);
}

static void ast_rtp_ice_set_authentication(struct ast_rtp_instance *instance, const char *ufrag, const char *password)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	if (ufrag) {
		ast_copy_string(rtp->remote_ufrag, ufrag, sizeof(rtp->remote_ufrag));	/* 257, bounded */
	}
	if (password) {
		ast_copy_string(rtp->remote_pwd, password, sizeof(rtp->remote_pwd));
	}
}

static const char *ast_rtp_ice_get_ufrag(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->local_ufrag;
}

static const char *ast_rtp_ice_get_password(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->local_pwd;
}

/* One HOST candidate, component 1 (rtcp-mux), UDP, the BOUND LOCAL address. A4's SDP glue overrides the
 * advertised address with externaddr/media_address when configured (channel-owned NAT mapping). */
static struct ao2_container *ast_rtp_ice_get_local_candidates(struct ast_rtp_instance *instance)
{
	struct ao2_container *cands;
	struct ast_rtp_engine_ice_candidate *c;
	struct ast_sockaddr local = { {0,} };

	if (!(cands = ao2_container_alloc(1, ice_cand_hash, ice_cand_cmp))) {
		return NULL;
	}
	if (!(c = ao2_alloc(sizeof(*c), ice_cand_dtor))) {
		ao2_ref(cands, -1);
		return NULL;
	}
	ast_rtp_instance_get_local_address(instance, &local);
	ast_sockaddr_copy(&c->address, &local);
	c->id = AST_RTP_ICE_COMPONENT_RTP;
	c->type = AST_RTP_ICE_CANDIDATE_TYPE_HOST;
	c->transport = ast_strdup("UDP");
	c->foundation = ast_strdup("1");
	if (!c->transport || !c->foundation) {
		ao2_ref(c, -1);		/* dtor frees the partial strdups (NULL-safe) */
		ao2_ref(cands, -1);
		return NULL;
	}
	/* RFC 8445 §5.1.2.1: priority = 2^24*typepref(126) + 2^8*localpref(65535) + (256-component). */
	c->priority = (126 << 24) | (65535 << 8) | (256 - AST_RTP_ICE_COMPONENT_RTP);
	ao2_link(cands, c);
	ao2_ref(c, -1);
	return cands;
}

static void ast_rtp_ice_add_remote_candidate(struct ast_rtp_instance *instance, const struct ast_rtp_engine_ice_candidate *candidate)
{
	/* ICE-lite never pairs/probes remote candidates (RFC 8445 §2.5); we learn the peer from the
	 * connectivity-check source. Accept-and-ignore so A4's parser can call us unconditionally (this
	 * also ignores remote srflx/relay — the A1 carry-over). */
	(void) instance;
	(void) candidate;
}

static void ast_rtp_ice_ice_lite(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	rtp->ice_lite = 1;	/* peer is also lite — irrelevant to us; record only */
}

static void ast_rtp_ice_set_role(struct ast_rtp_instance *instance, enum ast_rtp_ice_role role)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	(void) role;
	rtp->ice_role = AST_RTP_ICE_ROLE_CONTROLLED;	/* a lite agent MUST be controlled (RFC 8445 §6.1.1) */
}

static void ast_rtp_ice_start(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	rtp->ice_active = 1;	/* arm the responder; we never initiate a check (lite) */
}

static void ast_rtp_ice_stop(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	rtp->ice_active = 0;
	rtp->ice_complete = 0;
	ast_sockaddr_setnull(&rtp->ice_peer);
}

static struct ast_rtp_engine_ice gabpbx_ice = {
	.set_authentication = ast_rtp_ice_set_authentication,
	.add_remote_candidate = ast_rtp_ice_add_remote_candidate,
	.start = ast_rtp_ice_start,
	.stop = ast_rtp_ice_stop,
	.get_ufrag = ast_rtp_ice_get_ufrag,
	.get_password = ast_rtp_ice_get_password,
	.get_local_candidates = ast_rtp_ice_get_local_candidates,
	.ice_lite = ast_rtp_ice_ice_lite,
	.set_role = ast_rtp_ice_set_role,
};
#endif /* HAVE_OPENSSL */

/* RTP Engine Declaration */
/* RFC 8843 §9 / RFC 8285: configure the MID header extension we stamp on egressing bundled RTP. ext_id 0
 * disables it; audio_mid/video_mid are the a=mid tokens of the bundled m= lines. */
static int ast_rtp_set_mid_ext(struct ast_rtp_instance *instance, int ext_id, const char *audio_mid, const char *video_mid)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (!rtp) {
		return -1;
	}
	rtp->mid_ext_id = (ext_id > 0 && ext_id <= 14) ? ext_id : 0;	/* one-byte extension ids are 1..14 (RFC 8285) */
	ast_copy_string(rtp->mid_value_audio, S_OR(audio_mid, ""), sizeof(rtp->mid_value_audio));
	ast_copy_string(rtp->mid_value_video, S_OR(video_mid, ""), sizeof(rtp->mid_value_video));
	return 0;
}

static struct ast_rtp_engine gabpbx_rtp_engine = {
	.name = "gabpbx",
	.new = ast_rtp_new,
	.destroy = ast_rtp_destroy,
	.dtmf_begin = ast_rtp_dtmf_begin,
	.dtmf_end = ast_rtp_dtmf_end,
	.dtmf_end_with_duration = ast_rtp_dtmf_end_with_duration,
	.dtmf_mode_set = ast_rtp_dtmf_mode_set,
	.dtmf_mode_get = ast_rtp_dtmf_mode_get,
	.update_source = ast_rtp_update_source,
	.change_source = ast_rtp_change_source,
	.write = ast_rtp_write,
	.read = ast_rtp_read,
	.prop_set = ast_rtp_prop_set,
	.fd = ast_rtp_fd,
	.remote_address_set = ast_rtp_remote_address_set,
	.alt_remote_address_set = ast_rtp_alt_remote_address_set,
	.red_init = rtp_red_init,
	.red_buffer = rtp_red_buffer,
	.local_bridge = ast_rtp_local_bridge,
	.get_stat = ast_rtp_get_stat,
	.dtmf_compatible = ast_rtp_dtmf_compatible,
	.stun_request = ast_rtp_stun_request,
	.stop = ast_rtp_stop,
	.qos = ast_rtp_qos_set,
	.sendcng = ast_rtp_sendcng,
	.activate = ast_rtp_activate,	/* WebRTC A2: drives the active-side DTLS handshake */
	.set_mid_ext = ast_rtp_set_mid_ext,	/* RFC 8843 §9 / RFC 8285 MID header extension */
#ifdef HAVE_OPENSSL
	.dtls = &gabpbx_dtls,		/* WebRTC A2 */
	.ice = &gabpbx_ice,		/* WebRTC A3 — ICE-lite */
#endif
};

static inline int rtp_debug_test_addr(struct ast_sockaddr *addr)
{
	if (!rtpdebug) {
		return 0;
	}
	if (!ast_sockaddr_isnull(&rtpdebugaddr)) {
		if (rtpdebugport) {
			return (ast_sockaddr_cmp(&rtpdebugaddr, addr) == 0); /* look for RTP packets from IP+Port */
		} else {
			return (ast_sockaddr_cmp_addr(&rtpdebugaddr, addr) == 0); /* only look for RTP packets from IP */
		}
	}

	return 1;
}

static inline int rtcp_debug_test_addr(struct ast_sockaddr *addr)
{
	if (!rtcpdebug) {
		return 0;
	}
	if (!ast_sockaddr_isnull(&rtcpdebugaddr)) {
		if (rtcpdebugport) {
			return (ast_sockaddr_cmp(&rtcpdebugaddr, addr) == 0); /* look for RTCP packets from IP+Port */
		} else {
			return (ast_sockaddr_cmp_addr(&rtcpdebugaddr, addr) == 0); /* only look for RTCP packets from IP */
		}
	}

	return 1;
}

#ifdef HAVE_OPENSSL
/* ===== WebRTC A3: ICE-lite STUN responder (RFC 8445 §7.3 / RFC 5389), hand-rolled (main/stun.c is
 * RFC 3489 legacy). Runs under ao2_lock(instance) from the demux. SILENT-DROP on any failure
 * (anti-reflector, RFC 5389 §7.3.0; the browser retransmits). ===== */
#define ICE_STUN_MAGIC_COOKIE       0x2112a442u
#define ICE_STUN_BINDING_REQUEST    0x0001
#define ICE_STUN_BINDING_SUCCESS    0x0101
#define ICE_ATTR_USERNAME           0x0006
#define ICE_ATTR_MESSAGE_INTEGRITY  0x0008
#define ICE_ATTR_XOR_MAPPED_ADDRESS 0x0020
#define ICE_ATTR_USE_CANDIDATE      0x0025
#define ICE_ATTR_FINGERPRINT        0x8028
#define ICE_FINGERPRINT_XOR         0x5354554eu

struct ice_stun_hdr {
	uint16_t msgtype;
	uint16_t msglen;	/* EXCLUDES the 20-byte header */
	uint32_t cookie;
	uint8_t  tid[12];
} __attribute__((packed));

struct ice_stun_attr {
	uint16_t type;
	uint16_t len;		/* value length BEFORE 4-byte padding */
} __attribute__((packed));

/* STUN FINGERPRINT CRC-32 (IEEE, reflected, poly 0xEDB88320), RFC 5389 §15.5. Self-contained. */
static uint32_t ice_crc32_table[256];
/* Built once at module load (no lazy-init data race). */
static void ice_crc32_init(void)
{
	uint32_t c;
	int k, j;
	for (k = 0; k < 256; k++) {
		c = k;
		for (j = 0; j < 8; j++) {
			c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
		}
		ice_crc32_table[k] = c;
	}
}
static uint32_t ice_crc32(const uint8_t *p, size_t n)
{
	uint32_t crc = 0xffffffffu;
	size_t i;

	for (i = 0; i < n; i++) {
		crc = ice_crc32_table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
	}
	return crc ^ 0xffffffffu;
}

/* HMAC-SHA1 over msg keyed on the ice-pwd (short-term cred, RFC 5389 §15.4). 20-byte digest. OpenSSL. */
static int ice_hmac_sha1(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen, uint8_t out[20])
{
	unsigned int outlen = 20;
	memset(out, 0, 20);	/* deterministic on failure — never emit uninitialised stack on the wire */
	return (HMAC(EVP_sha1(), key, (int) keylen, msg, msglen, out, &outlen) && outlen == 20) ? 0 : -1;
}

/* Append a 4-byte-padded TLV; returns the new offset. Caller guarantees the buffer fits. */
static int ice_put_attr(uint8_t *out, int off, uint16_t type, const void *val, int vlen)
{
	struct ice_stun_attr *a = (struct ice_stun_attr *) (out + off);
	int padded = (vlen + 3) & ~3;

	a->type = htons(type);
	a->len = htons((uint16_t) vlen);
	memcpy(out + off + sizeof(*a), val, vlen);
	if (padded > vlen) {
		memset(out + off + sizeof(*a) + vlen, 0, padded - vlen);
	}
	return off + sizeof(*a) + padded;
}

/* Build XOR-MAPPED-ADDRESS value for sa (RFC 5389 §15.2). Raw sockaddr access keeps everything in
 * network order (avoids the host/network ambiguity of ast_sockaddr_ipv4). Returns 8 (v4) / 20 (v6). */
static int ice_build_xor_mapped(struct ast_sockaddr *sa, struct ice_stun_hdr *req, uint8_t *xma)
{
	uint16_t xport;

	xma[0] = 0;
	if (sa->ss.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *) &sa->ss;
		uint32_t xaddr = sin->sin_addr.s_addr ^ htonl(ICE_STUN_MAGIC_COOKIE);
		xport = sin->sin_port ^ htons((uint16_t)(ICE_STUN_MAGIC_COOKIE >> 16));
		xma[1] = 0x01;	/* family IPv4 */
		memcpy(xma + 2, &xport, 2);
		memcpy(xma + 4, &xaddr, 4);
		return 8;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sa->ss;
		uint8_t mask[16];
		uint32_t ck = htonl(ICE_STUN_MAGIC_COOKIE);
		int i;
		xport = sin6->sin6_port ^ htons((uint16_t)(ICE_STUN_MAGIC_COOKIE >> 16));
		xma[1] = 0x02;	/* family IPv6 */
		memcpy(xma + 2, &xport, 2);
		memcpy(mask, &ck, 4);
		memcpy(mask + 4, req->tid, 12);	/* X-Address mask = cookie || transaction-id */
		for (i = 0; i < 16; i++) {
			xma[4 + i] = sin6->sin6_addr.s6_addr[i] ^ mask[i];
		}
		return 20;
	}
}

/* The responder. Runs LOCKED (demux ao2_lock). Silent-drop on ANY failure. On a valid authenticated
 * check: learn the source as the peer + set the RTP remote address + reply success; on USE-CANDIDATE:
 * mark ice_complete + fire the active DTLS handshake (RFC 8445 §7.3.2 / §8.2). */
static void ice_handle_stun(struct ast_rtp_instance *instance, struct ast_rtp *rtp,
	unsigned char *buf, int len, struct ast_sockaddr *sa)
{
	struct ice_stun_hdr *h = (struct ice_stun_hdr *) buf;
	int mlen, off, mi_off = -1, fp_off = -1, has_use_candidate = 0;
	const unsigned char *username = NULL;
	int username_len = 0;
	uint8_t calc[20], out[512], xma[20], mi[20];
	uint16_t saved;
	uint32_t fp;
	size_t ul;
	int oo, xlen;
	struct ice_stun_hdr *r;

	/* Hardening: answer only when ICE was negotiated AND we hold non-empty credentials (defense in
	 * depth vs a CSPRNG fail-open — an empty pwd is a publicly-known HMAC key; ast_rtp_new already
	 * fails the instance on CSPRNG failure, this is belt-and-suspenders). */
	if (!rtp->ice_active || ast_strlen_zero(rtp->local_ufrag) || ast_strlen_zero(rtp->local_pwd)) {
		return;
	}

	/* 0. Frame sanity. */
	if (len < (int) sizeof(*h)) return;
	if (ntohs(h->msgtype) != ICE_STUN_BINDING_REQUEST) return;
	if (ntohl(h->cookie) != ICE_STUN_MAGIC_COOKIE) return;	/* not RFC 5389 → drop (anti-spoof) */
	mlen = ntohs(h->msglen);
	if (20 + mlen > len) return;

	/* 1. Single bounds-checked, non-destructive TLV walk. */
	for (off = sizeof(*h); off + (int) sizeof(struct ice_stun_attr) <= 20 + mlen; ) {
		struct ice_stun_attr *a = (struct ice_stun_attr *) (buf + off);
		int atype = ntohs(a->type), alen = ntohs(a->len);
		int vstart = off + sizeof(*a);
		int padded = (alen + 3) & ~3;

		if (vstart + alen > 20 + mlen) return;	/* truncated attr */
		switch (atype) {
		case ICE_ATTR_USERNAME:
			if (mi_off < 0) {	/* HIGH2: ignore attrs after MESSAGE-INTEGRITY (RFC 5389) — unauthenticated */
				username = buf + vstart;
				username_len = alen;
			}
			break;
		case ICE_ATTR_MESSAGE_INTEGRITY:
			if (alen != 20) return;	/* hardening 3: fixed length */
			mi_off = off;
			break;
		case ICE_ATTR_FINGERPRINT:
			if (alen != 4) return;	/* hardening 3 */
			fp_off = off;
			break;
		case ICE_ATTR_USE_CANDIDATE:
			if (mi_off < 0) {	/* HIGH2: only an authenticated USE-CANDIDATE (before MI) may nominate */
				has_use_candidate = 1;
			}
			break;
		default:
			break;	/* PRIORITY / ICE-CONTROLLING etc.: parsed past, never acted on (we are controlled) */
		}
		off = vstart + padded;
	}

	/* 2. FINGERPRINT must be present, LAST (hardening 3), and valid (RFC 5389 §15.5). */
	if (fp_off < 0 || fp_off + (int) sizeof(struct ice_stun_attr) + 4 != 20 + mlen) return;
	if ((ice_crc32(buf, fp_off) ^ ICE_FINGERPRINT_XOR)
		!= ntohl(*(uint32_t *)(buf + fp_off + sizeof(struct ice_stun_attr)))) {
		return;
	}

	/* 3. USERNAME + MI present, and USERNAME prefix == our local_ufrag (RFC 8445 §7.3). */
	if (!username || mi_off < 0) return;
	ul = strlen(rtp->local_ufrag);
	if ((size_t) username_len < ul + 1 || memcmp(username, rtp->local_ufrag, ul) != 0 || username[ul] != ':') {
		return;
	}

	/* 4. MESSAGE-INTEGRITY: HMAC-SHA1 with OUR local_pwd over buf[0..mi_off), header length temporarily
	 *    rewritten to cover through MI (RFC 5389 §15.4). Restored afterwards (non-destructive). */
	saved = h->msglen;
	h->msglen = htons((uint16_t)(mi_off - 20 + 24));
	if (ice_hmac_sha1((const uint8_t *) rtp->local_pwd, strlen(rtp->local_pwd), buf, mi_off, calc)) {
		h->msglen = saved;
		return;	/* HMAC failure — silent drop */
	}
	h->msglen = saved;
	if (memcmp(calc, buf + mi_off + sizeof(struct ice_stun_attr), 20) != 0) {
		return;	/* MI mismatch — silent drop */
	}


	/* 5. AUTHENTICATED. LATCH the RTP remote address to the live authenticated check source for the WHOLE call
	 *    (symmetric-RTP, like Asterisk's pjproject aiming at valid_check->rcand->addr). The controlling browser
	 *    nominates several candidates and then runs RFC 7675 consent freshness ONLY on its SELECTED pair, which
	 *    can differ from the first/transient USE-CANDIDATE; a WebRTC browser binds its DTLS to that selected pair
	 *    (RFC 8445 §2.3) and ignores DTLS on any other candidate. Freezing on the first nominated pair misdirects
	 *    our ServerHello + SRTP to a dead 5-tuple → no audio. Updating on EVERY authenticated check follows the
	 *    selected pair, and is SAFE because the MESSAGE-INTEGRITY (our secret local_pwd, exchanged only over the
	 *    secure SIP/WSS signaling) cannot be forged — a spoofer cannot move the tuple.
	 *    ┌─ DO NOT re-introduce the 1.3.3 USE-CANDIDATE-ONLY latch, and DO NOT add PRIORITY pinning ──────────┐
	 *    │ Both were TRIED and BROKE AUDIO on the offerer/fork path, so both are REJECTED (after               │
	 *    │ review, safe to drop). (a) Gating this latch on `has_use_candidate` (the 1.3.3 model) leaves the RTP│
	 *    │ remote on a stale pair for offerer/fork calls where the browser never re-nominates → ServerHello to │
	 *    │ a dead 5-tuple → DTLS never completes → DEAF. (b) A PRIORITY non-downgrade guard pins a non-media   │
	 *    │ candidate for the same reason. KEEP "latest authenticated check wins" (LATCH-ALWAYS). This debug    │
	 *    │ patch adds ONLY logging below — no datapath change. Use "rtp set debug ice on" to watch the latch.  │
	 *    └─────────────────────────────────────────────────────────────────────────────────────────────────────┘ */
	ast_sockaddr_copy(&rtp->ice_peer, sa);
	ast_rtp_instance_set_remote_address(instance, sa);
	if (rtpicedebug && (!rtp->latch_seen || ast_sockaddr_cmp(&rtp->last_latch, sa))) {
		/* first latch + every latch SOURCE CHANGE (the tuple port-flap behind the intermittent/fork bugs) */
		char *p_new = ast_strdupa(ast_sockaddr_stringify(sa));
		char *p_old = ast_strdupa(ast_sockaddr_stringify(&rtp->last_latch));
		ast_verbose("ICE-DBG latch inst=%p rtp=%p src=%s old=%s first=%d use_candidate=%d ice_complete=%d dtls_conn=%d dtls_setup=%d\n",
			instance, rtp, p_new, p_old, !rtp->latch_seen, has_use_candidate, rtp->ice_complete,
			(int)rtp->dtls.connection, (int)rtp->dtls.dtls_setup);
		ast_sockaddr_copy(&rtp->last_latch, sa);
		rtp->latch_seen = 1;
	}

	/* 6. Build + send the success Binding Response FIRST (MED2 — the browser confirms the pair before
	 *    our ClientHello arrives): XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT (last). */
	r = (struct ice_stun_hdr *) out;
	r->msgtype = htons(ICE_STUN_BINDING_SUCCESS);
	r->cookie = htonl(ICE_STUN_MAGIC_COOKIE);
	memcpy(r->tid, h->tid, sizeof(r->tid));
	oo = sizeof(*r);

	xlen = ice_build_xor_mapped(sa, h, xma);
	oo = ice_put_attr(out, oo, ICE_ATTR_XOR_MAPPED_ADDRESS, xma, xlen);

	r->msglen = htons((uint16_t)((oo - 20) + 24));	/* cover through MI before hashing */
	if (ice_hmac_sha1((const uint8_t *) rtp->local_pwd, strlen(rtp->local_pwd), out, oo, mi)) {
		return;	/* HMAC failure — do not emit a response with a bad MI */
	}
	oo = ice_put_attr(out, oo, ICE_ATTR_MESSAGE_INTEGRITY, mi, 20);

	r->msglen = htons((uint16_t)((oo - 20) + 8));	/* cover through FINGERPRINT before the CRC */
	fp = htonl(ice_crc32(out, oo) ^ ICE_FINGERPRINT_XOR);
	oo = ice_put_attr(out, oo, ICE_ATTR_FINGERPRINT, &fp, 4);

	rtp_raw_sendto(rtp, out, oo, sa, 0);

	/* 7. USE-CANDIDATE → selected pair → ICE complete; fire the active DTLS handshake AFTER the success
	 *    reply + remote address are set (MED2). dtls_perform_handshake re-locks ao2 (recursive — safe);
	 *    no-op on the passive side. */
	if (has_use_candidate && !rtp->ice_complete) {
		rtp->ice_complete = 1;
		if (rtpicedebug) {	/* the nominated/selected pair — the first USE-CANDIDATE that completes ICE */
			char *p = ast_strdupa(ast_sockaddr_stringify(sa));
			ast_verbose("ICE-DBG nominate inst=%p rtp=%p selected_pair=%s dtls_conn=%d dtls_setup=%d\n",
				instance, rtp, p, (int)rtp->dtls.connection, (int)rtp->dtls.dtls_setup);
		}
		dtls_perform_handshake(instance, rtp);
	}
}
#endif /* HAVE_OPENSSL */

static int __rtp_recvfrom(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa, int rtcp)
{
	int len;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_srtp *srtp = ast_rtp_instance_get_srtp(instance);
#ifdef HAVE_OPENSSL
	int demux_guard = 0;
#endif

#ifdef HAVE_OPENSSL
read_again:
#endif
	if ((len = ast_recvfrom(rtcp ? rtp->rtcp->s : rtp->s, buf, size, flags, sa)) < 0) {
#ifdef HAVE_OPENSSL
		/* B4: classify a non-EAGAIN socket error on a WebRTC leg. A transient ICMP-unreachable during ICE
		 * probing (ice_complete=0) is benign; the same errno after DTLS is up is real media loss. LOG ONLY —
		 * the return is unchanged; ast_rtp_read maps only EAGAIN + the selected transient WebRTC errnos to
		 * ast_null_frame (the 1be4b99 fix), other errnos still hang up. */
		if (rtpicedebug && errno != EAGAIN && errno != EWOULDBLOCK && rtp->dtls.ssl) {
			ast_verbose("ICE-DBG recv-err inst=%p rtp=%p errno=%d rtcp=%d ice_active=%d ice_complete=%d dtls_conn=%d\n",
				instance, rtp, errno, rtcp, rtp->ice_active, rtp->ice_complete, (int)rtp->dtls.connection);
		}
#endif
	   return len;
	}

#ifdef HAVE_OPENSSL
	/* WebRTC A2: RFC 7983 first-byte demux. Active ONLY when DTLS is set up on this instance, so the
	 * plain-RTP/SRTP path below is byte-for-byte unchanged for non-WebRTC calls. Consumed control
	 * packets loop to the next datagram (C1: never surfaced to ast_rtp_read as a short read), and an
	 * EAGAIN from ast_recvfrom exits cleanly above (ast_rtp_read maps it to ast_null_frame, no log). */
	if (len > 0 && !rtcp && rtp->dtls.ssl) {
		/* Only the RTP socket carries the muxed DTLS/STUN (rtcp-mux); the separate RTCP socket, if the
		 * SRTP-install T39 workaround allocated one, must NOT feed this single DTLS association (LOW8). */
		unsigned char first = ((unsigned char *) buf)[0];

		/* Defensive bound: a sustained DTLS/STUN flood on the read path must not spin the loop;
		 * yield to ast_rtp_read (EAGAIN -> ast_null_frame, no log) after draining a burst. */
		if (++demux_guard > 200) {
			errno = EAGAIN;
			return -1;
		}
		if (first <= 3) {
			/* STUN — A3 ICE-lite responder, under the SAME ao2_lock the DTLS branch takes
			 * (the responder re-locks via dtls_perform_handshake on USE-CANDIDATE — ao2 is recursive). */
			ao2_lock(instance);
			ice_handle_stun(instance, rtp, (unsigned char *) buf, len, sa);
			ao2_unlock(instance);
			goto read_again;
		}
		if (first >= 20 && first <= 63) {
			/* DTLS record — feed OpenSSL under the SAME ao2_lock the A1 wrappers take
			 * (lock order channel->pvt->instance->peer; we are already below pvt here).
			 *
			 * FIX 2 (RFC 5763 §6.7.1 — DTLS rides the ICE-validated pair). When ICE is in use
			 * (ice_active: the lite responder is armed), gate the record on the source matching
			 * the ICE-validated peer (rtp->ice_peer, latched by ice_handle_stun on each
			 * MESSAGE-INTEGRITY-authenticated check — our analogue of upstream's
			 * ice_media_started gate; NOTE this is a single selected-pair LATCH of the latest authenticated STUN source, NOT upstream's full active-remote-candidate list — sufficient for the current ICE-lite latch-always single-live-tuple model; a valid-tuple ring would be the stricter form, res_rtp_asterisk.c). Until a
			 * STUN check has validated a peer ice_peer is null → drop (mirrors upstream's "ICE
			 * not completed yet"). This closes a pre-validation DoS: an attacker who can deliver
			 * UDP to our advertised host candidate could otherwise (a) prematurely commit our
			 * DTLS role to PASSIVE before the SDP answer, and (b) inject a record that drives a
			 * fatal SSL error tearing down an active call. Dropping (read next datagram) — NOT
			 * failing the read — preserves the call. The post-handshake fingerprint memcmp still
			 * blocks MITM; this adds the pre-validation gate. The normal handshake from the
			 * validated peer is unaffected: ice_handle_stun latches ice_peer (and fires the
			 * handshake) on the same authenticated source the DTLS records then come from. When
			 * ICE is not in use (plain non-WebRTC DTLS, ice_active == 0) the gate is skipped, so
			 * that path is byte-for-byte unchanged. */
			int dres;
			if (rtp->ice_active &&
				(ast_sockaddr_isnull(&rtp->ice_peer) || ast_sockaddr_cmp(&rtp->ice_peer, sa))) {
				if (rtpicedebug && (!rtp->dtls_drop_seen || ast_sockaddr_cmp(&rtp->last_dtls_drop, sa))) {
					/* A DTLS record (rec_first=22 => ClientHello) from a source that is NOT the ICE-latched
					 * peer is dropped here. If the latch is on the WRONG pair this is exactly why DTLS never
					 * completes (offerer/fork deaf class). LOG ONLY — the drop behavior is unchanged. */
					char *p_src = ast_strdupa(ast_sockaddr_stringify(sa));
					char *p_peer = ast_strdupa(ast_sockaddr_stringify(&rtp->ice_peer));
					ast_verbose("ICE-DBG dtls-drop inst=%p rtp=%p rec_first=%u rec_src=%s ice_peer=%s peer_null=%d ice_complete=%d dtls_conn=%d\n",
						instance, rtp, first, p_src, p_peer, ast_sockaddr_isnull(&rtp->ice_peer),
						rtp->ice_complete, (int)rtp->dtls.connection);
					ast_sockaddr_copy(&rtp->last_dtls_drop, sa);
					rtp->dtls_drop_seen = 1;
				}
				goto read_again;
			}
			ao2_lock(instance);
			dres = dtls_srtp_handle_record(instance, rtp, buf, len);
			ao2_unlock(instance);
			if (dres < 0) {
				/* DTLS failed (fingerprint mismatch / fatal handshake) — fail the read so the
				 * channel layer tears the call down (RFC 5763 §5 fail-closed). */
				errno = EIO;
				return -1;
			}
			goto read_again;
		}
		if (first < 128 || first > 191) {
			/* C6: RFC 7983 non-RTP/RTCP range — drop, read next. */
			goto read_again;
		}
		/* 128-191 is RTP OR, under rtcp-mux (WebRTC always mandates it), muxed (S)RTCP on the same
		 * socket. RFC 5761 §4: an RTCP packet's type (byte 1, with the marker bit masked) is in 64-95
		 * (RTP forbids those PTs); the 8-byte SRTCP header incl. the PT is in the clear.
		 *
		 * FIX 1: process inbound muxed (S)RTCP instead of dropping it (previously dropped for v1, which
		 * starved ast_rtp_get_stat of remote SR/RR and ignored inbound RTCP BYE/feedback — relevant now
		 * that video ships). When the DTLS-SRTP context is EXISTING, SRTCP-unprotect the datagram in place
		 * (rtcp=1 → SRTCP profile) and feed the cleartext compound packet into the shared RTCP parser
		 * (ast_rtcp_interpret), the exact same code path the standalone RTCP socket uses. FAIL-SAFE: if the
		 * unprotect fails (auth/replay) drop THAT datagram only (goto read_again) — never -1, which would
		 * hang the call up. While DTLS is still NEW there is no SRTCP context yet, so keep dropping. The
		 * parser needs rtp->rtcp (it accounts into it); if RTCP was never set up on this instance, drop.
		 * Plain non-DTLS RTP never reaches here (outer rtp->dtls.ssl gate), so it is byte-for-byte
		 * unaffected, and the SRTP/SRTCP unprotect is the same res_srtp entry point used elsewhere. */
		if (len >= 2 && (((unsigned char *) buf)[1] & 0x7f) >= 64 && (((unsigned char *) buf)[1] & 0x7f) <= 95) {
			struct ast_srtp *rtcp_srtp;
			int rtcp_len = len;

			if (rtp->dtls.connection != AST_RTP_DTLS_CONNECTION_EXISTING || !rtp->rtcp) {
				/* No SRTCP key yet (DTLS still handshaking) or no RTCP accounting context: drop. */
				goto read_again;
			}
			rtcp_srtp = ast_rtp_instance_get_srtp(instance);
			if (res_srtp && rtcp_srtp
				&& res_srtp->unprotect(rtcp_srtp, buf, &rtcp_len, 1) < 0) {
				/* SRTCP unprotect failed for this datagram (auth/replay) — drop it, keep the call. */
				goto read_again;
			}
			ao2_lock(instance);
			ast_rtcp_interpret(instance, (unsigned int *) buf, rtcp_len, sa);
			ao2_unlock(instance);
			goto read_again;
		}
		/* WebRTC: never ACCEPT media before DTLS-SRTP is established. While the connection is NEW there is
		 * no SRTP context yet, so the res_srtp/unprotect guard below short-circuits and this 128-191 RTP
		 * datagram would be surfaced as PLAIN cleartext media (RFC 8827 §6.5: media MUST NOT be sent/received
		 * over plain unencrypted RTP/RTCP). STUN (first<=3) and DTLS records (first 20-63) are handled and
		 * looped above, so they never reach here; only the RTP/SRTP media class is dropped pre-establishment.
		 * connection flips to EXISTING on handshake completion + SRTP install (dtls_srtp_finish_negotiation).
		 * Gated by the rtp->dtls.ssl outer condition, so non-WebRTC RTP is byte-for-byte unaffected. Mirrors
		 * the outbound CONNECTION_NEW guard in __rtp_sendto. */
		if (rtp->dtls.connection == AST_RTP_DTLS_CONNECTION_NEW) {
			goto read_again;
		}
		/* else 128-191 RTP, DTLS established → fall through to the unchanged SRTP path. */
	}

	/* The demux may have installed SRTP on the handshake-completing record (MED5): re-fetch the srtp
	 * context so the first post-handshake media packet drained in this same loop is unprotected. */
	srtp = ast_rtp_instance_get_srtp(instance);
#endif

	if (res_srtp && srtp && res_srtp->unprotect(srtp, buf, &len, rtcp) < 0) {
#ifdef HAVE_OPENSSL
		/* B3: SRTP unprotect failure on a WebRTC leg (wrong key / replay / forgery). Rate-limited. LOG ONLY;
		 * the return -1 is unchanged. Distinguishes "DTLS up but media not decrypting" from "no media". */
		if (rtpicedebug && rtp->dtls.ssl) {
			rtp->srtp_auth_fail++;
			if (rtp->srtp_auth_fail <= 3 || (rtp->srtp_auth_fail % 100) == 0) {
				ast_verbose("ICE-DBG srtp-authfail inst=%p rtp=%p rtcp=%d count=%u\n",
					instance, rtp, rtcp, rtp->srtp_auth_fail);
			}
		}
#endif
	   return -1;
	}

#ifdef HAVE_OPENSSL
	/* B3: first successful SRTP decrypt on a WebRTC leg — proves the SRTP pipeline actually decrypts (distinct
	 * from ICE-RXDBG, which logs post-parse in ast_rtp_read). One-shot, log only. */
	if (rtpicedebug && !rtcp && rtp->dtls.ssl && res_srtp && srtp && !rtp->srtp_rx_logged && len >= 12) {
		unsigned int *rh = (unsigned int *) buf;
		rtp->srtp_rx_logged = 1;
		ast_verbose("ICE-DBG srtp-first-decrypt inst=%p rtp=%p pt=%d ssrc=%u len=%d\n",
			instance, rtp, (int)((ntohl(rh[0]) >> 16) & 0x7f), (unsigned int) ntohl(rh[2]), len);
	}
#endif

	return len;
}

static int rtcp_recvfrom(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_recvfrom(instance, buf, size, flags, sa, 1);
}

static int rtp_recvfrom(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_recvfrom(instance, buf, size, flags, sa, 0);
}

static int __rtp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa, int rtcp)
{
	int len = size;
	void *temp = buf;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_srtp *srtp = ast_rtp_instance_get_srtp(instance);

#ifdef HAVE_OPENSSL
	/* WebRTC: never emit media before DTLS-SRTP is established. While the connection is NEW there are no
	 * SRTP keys yet, so this path would send PLAIN RTP — leaking cleartext media and confusing the peer
	 * (RFC 5763 §6.10: media flows after the DTLS Finished). connection flips to EXISTING on handshake
	 * completion + key install (dtls_srtp_finish_negotiation). STUN/DTLS use rtp_raw_sendto (not this
	 * path); a non-WebRTC call has no dtls.ssl → unaffected. Mirrors Asterisk 22. */
	if (rtp->dtls.ssl && rtp->dtls.connection == AST_RTP_DTLS_CONNECTION_NEW) {
		return 0;
	}
#endif

	if (res_srtp && srtp && res_srtp->protect(srtp, &temp, &len, rtcp) < 0) {
	   return -1;
	}

	return ast_sendto(rtcp ? rtp->rtcp->s : rtp->s, temp, len, flags, sa);
}

static int rtcp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_sendto(instance, buf, size, flags, sa, 1);
}

static int rtp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_sendto(instance, buf, size, flags, sa, 0);
}

static int rtp_get_rate(format_t subclass)
{
	return (subclass == AST_FORMAT_G722) ? 8000 : ast_format_rate(subclass);
}

static unsigned int ast_rtcp_calc_interval(struct ast_rtp *rtp)
{
	unsigned int interval;
	/*! \todo XXX Do a more reasonable calculation on this one
	 * Look in RFC 3550 Section A.7 for an example*/
	interval = rtcpinterval;
	return interval;
}

/*! \brief Calculate normal deviation */
static double normdev_compute(double normdev, double sample, unsigned int sample_count)
{
	normdev = normdev * sample_count + sample;
	sample_count++;

	return normdev / sample_count;
}

static double stddev_compute(double stddev, double sample, double normdev, double normdev_curent, unsigned int sample_count)
{
/*
		for the formula check http://www.cs.umd.edu/~austinjp/constSD.pdf
		return sqrt( (sample_count*pow(stddev,2) + sample_count*pow((sample-normdev)/(sample_count+1),2) + pow(sample-normdev_curent,2)) / (sample_count+1));
		we can compute the sigma^2 and that way we would have to do the sqrt only 1 time at the end and would save another pow 2 compute
		optimized formula
*/
#define SQUARE(x) ((x) * (x))

	stddev = sample_count * stddev;
	sample_count++;

	return stddev +
		( sample_count * SQUARE( (sample - normdev) / sample_count ) ) +
		( SQUARE(sample - normdev_curent) / sample_count );

#undef SQUARE
}

static int create_new_socket(const char *type, int af)
{
	int sock = socket(af, SOCK_DGRAM, 0);

	if (sock < 0) {
		if (!type) {
			type = "RTP/RTCP";
		}
		ast_log(LOG_WARNING, "Unable to allocate %s socket: %s\n", type, strerror(errno));
	} else {
		long flags = fcntl(sock, F_GETFL);
		fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#ifdef SO_NO_CHECK
		if (nochecksums) {
			setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, &nochecksums, sizeof(nochecksums));
		}
#endif
	}

	return sock;
}

/*!
 * \internal
 * \brief Initializes sequence values and probation for learning mode.
 * \note This is an adaptation of pjmedia's pjmedia_rtp_seq_init function.
 *
 * \param rtp pointer to rtp struct used with the received rtp packet.
 * \param seq sequence number read from the rtp header
 */
static void rtp_learning_seq_init(struct ast_rtp *rtp, uint16_t seq)
{
	rtp->learning_max_seq = seq - 1;
	rtp->learning_probation = learning_min_sequential;
}

/*!
 * \internal
 * \brief Updates sequence information for learning mode and determines if probation/learning mode should remain in effect.
 * \note This function was adapted from pjmedia's pjmedia_rtp_seq_update function.
 *
 * \param rtp pointer to rtp struct used with the received rtp packet.
 * \param seq sequence number read from the rtp header
 * \return boolean value indicating if probation mode is active at the end of the function
 */
static int rtp_learning_rtp_seq_update(struct ast_rtp *rtp, uint16_t seq)
{
	int probation = 1;

	ast_debug(1, "%p -- probation = %d, seq = %d\n", rtp, rtp->learning_probation, seq);

	if (seq == rtp->learning_max_seq + 1) {
		/* packet is in sequence */
		rtp->learning_probation--;
		rtp->learning_max_seq = seq;
		if (rtp->learning_probation == 0) {
			probation = 0;
		}
	} else {
		rtp->learning_probation = learning_min_sequential - 1;
		rtp->learning_max_seq = seq;
	}

	return probation;
}

static int ast_rtp_new(struct ast_rtp_instance *instance,
		       struct sched_context *sched, struct ast_sockaddr *addr,
		       void *data)
{
	struct ast_rtp *rtp = NULL;
	int x, startplace;

	/* Create a new RTP structure to hold all of our data */
	if (!(rtp = ast_calloc(1, sizeof(*rtp)))) {
		return -1;
	}

	/* Set default parameters on the newly created RTP structure */
	rtp->ssrc = ast_random();
	rtp->seqno = ast_random() & 0xffff;
	/* WebRTC BUNDLE: the video sub-stream gets its own SSRC/seqno (used only when rtp->bundle). */
	rtp->v_ssrc = ast_random();
	rtp->v_seqno = ast_random() & 0xffff;
	//rtp->lastrxseqno = rtp->seqno;
	rtp->lostrtp = 0;
	rtp->strict_rtp_state = (strictrtp ? STRICT_RTP_LEARN : STRICT_RTP_OPEN);
	if (strictrtp) {
		rtp_learning_seq_init(rtp, (uint16_t)rtp->seqno);
	}

	/* Create a new socket for us to listen on and use */
	if ((rtp->s =
	     create_new_socket("RTP",
			       ast_sockaddr_is_ipv4(addr) ? AF_INET  :
			       ast_sockaddr_is_ipv6(addr) ? AF_INET6 : -1)) < 0) {
		ast_debug(1, "Failed to create a new socket for RTP instance '%p'\n", instance);
		ast_free(rtp);
		return -1;
	}

	/* Now actually find a free RTP port to use */
	x = (rtpend == rtpstart) ? rtpstart : (ast_random() % (rtpend - rtpstart)) + rtpstart;
	x = x & ~1;
	startplace = x;

	for (;;) {
		ast_sockaddr_set_port(addr, x);
		/* Try to bind, this will tell us whether the port is available or not */
		if (!ast_bind(rtp->s, addr)) {
			ast_debug(1, "Allocated port %d for RTP instance '%p'\n", x, instance);
			ast_rtp_instance_set_local_address(instance, addr);
			break;
		}

		x += 2;
		if (x > rtpend) {
			x = (rtpstart + 1) & ~1;
		}

		/* See if we ran out of ports or if the bind actually failed because of something other than the address being in use */
		if (x == startplace || errno != EADDRINUSE) {
			ast_log(LOG_ERROR, "Oh dear... we couldn't allocate a port for RTP instance '%p'\n", instance);
			close(rtp->s);
			ast_free(rtp);
			return -1;
		}
	}

	/* Record any information we may need */
	rtp->sched = sched;
#ifdef HAVE_OPENSSL
	/* WebRTC A2: sched-id sentinels (the ast_calloc above zeroed the rest of the DTLS state) */
	rtp->dtls.timeout_timer = -1;
	rtp->rekeyid = -1;
	/* WebRTC A3: generate our ICE-lite locals once (CSPRNG, RFC 8445 §5.4); the bind above set the
	 * local address so the host candidate is ready. FAIL CLOSED on CSPRNG failure — empty creds would
	 * be a publicly-known HMAC key (auth bypass + remote-address steering). */
	if (ice_rand_string(rtp->local_ufrag, sizeof(rtp->local_ufrag))
		|| ice_rand_string(rtp->local_pwd, sizeof(rtp->local_pwd))) {
		ast_log(LOG_ERROR, "Failed to generate ICE credentials (CSPRNG) for RTP instance '%p'\n", instance);
		close(rtp->s);
		ast_free(rtp);
		return -1;
	}
	rtp->ice_role = AST_RTP_ICE_ROLE_CONTROLLED;
#endif

	/* Associate the RTP structure with the RTP instance and be done */
	ast_rtp_instance_set_data(instance, rtp);

	return 0;
}

static int ast_rtp_destroy(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* Destroy the smoother that was smoothing out audio if present */
	if (rtp->smoother) {
		ast_smoother_free(rtp->smoother);
	}

#ifdef HAVE_OPENSSL
	/* WebRTC A2: free the DTLS association directly. At destroy the retransmit timer cannot be armed
	 * (an armed timer holds an instance ref, so the refcount could not have reached 0) and no other
	 * thread can reach this instance, so no lock and no timer-stop are needed here. */
	dtls_free_association(rtp);
#endif

	/* Close our own socket so we no longer get packets */
	if (rtp->s > -1) {
		close(rtp->s);
	}

	/* Destroy RTCP if it was being used */
	if (rtp->rtcp) {
		/*
		 * It is not possible for there to be an active RTCP scheduler
		 * entry at this point since it holds a reference to the
		 * RTP instance while it's active.
		 */
		close(rtp->rtcp->s);
		ast_free(rtp->rtcp);
	}

	/* Destroy RED if it was being used */
	if (rtp->red) {
		AST_SCHED_DEL(rtp->sched, rtp->red->schedid);
		ast_free(rtp->red);
	}

	/* Finally destroy ourselves */
	ast_free(rtp);

	return 0;
}

static int ast_rtp_dtmf_mode_set(struct ast_rtp_instance *instance, enum ast_rtp_dtmf_mode dtmf_mode)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	rtp->dtmfmode = dtmf_mode;
	return 0;
}

static enum ast_rtp_dtmf_mode ast_rtp_dtmf_mode_get(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->dtmfmode;
}

static int ast_rtp_dtmf_begin(struct ast_rtp_instance *instance, char digit)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int hdrlen = 12, res = 0, i = 0, payload = 101;
	char data[256];
	unsigned int *rtpheader = (unsigned int*)data;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* If we have no remote address information bail out now */
	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}

	/* Convert given digit into what we want to transmit */
	if ((digit <= '9') && (digit >= '0')) {
		digit -= '0';
	} else if (digit == '*') {
		digit = 10;
	} else if (digit == '#') {
		digit = 11;
	} else if ((digit >= 'A') && (digit <= 'D')) {
		digit = digit - 'A' + 12;
	} else if ((digit >= 'a') && (digit <= 'd')) {
		digit = digit - 'a' + 12;
	} else {
		ast_log(LOG_WARNING, "Don't know how to represent '%c'\n", digit);
		return -1;
	}

	/* Grab the payload that they expect the RFC2833 packet to be received in */
	payload = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(instance), 0, AST_RTP_DTMF);

	rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, 500000));
	rtp->send_duration = 160;
	rtp->lastdigitts = rtp->lastts + rtp->send_duration;

	/* Create the actual packet that we will be sending */
	rtpheader[0] = htonl((2 << 30) | (1 << 23) | (payload << 16) | (rtp->seqno));
	rtpheader[1] = htonl(rtp->lastdigitts);
	rtpheader[2] = htonl(rtp->ssrc);

	/* Actually send the packet */
	for (i = 0; i < 2; i++) {
		rtpheader[3] = htonl((digit << 24) | (0xa << 16) | (rtp->send_duration));
		res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 4, 0, &remote_address);
		if (res < 0) {
			ast_log(LOG_ERROR, "RTP Transmission error to %s: %s\n",
				ast_sockaddr_stringify(&remote_address),
				strerror(errno));
		}
		if (rtp_debug_test_addr(&remote_address)) {
			ast_verbose("Sent RTP DTMF packet to %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
				    ast_sockaddr_stringify(&remote_address),
				    payload, rtp->seqno, rtp->lastdigitts, res - hdrlen);
		}
		rtp->seqno++;
		rtp->send_duration += 160;
		rtpheader[0] = htonl((2 << 30) | (payload << 16) | (rtp->seqno));
	}

	/* Record that we are in the process of sending a digit and information needed to continue doing so */
	rtp->sending_digit = 1;
	rtp->send_digit = digit;
	rtp->send_payload = payload;

	return 0;
}

static int ast_rtp_dtmf_continuation(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int hdrlen = 12, res = 0;
	char data[256];
	unsigned int *rtpheader = (unsigned int*)data;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* Make sure we know where the other side is so we can send them the packet */
	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}

	/* Actually create the packet we will be sending */
	rtpheader[0] = htonl((2 << 30) | (1 << 23) | (rtp->send_payload << 16) | (rtp->seqno));
	rtpheader[1] = htonl(rtp->lastdigitts);
	rtpheader[2] = htonl(rtp->ssrc);
	rtpheader[3] = htonl((rtp->send_digit << 24) | (0xa << 16) | (rtp->send_duration));
	rtpheader[0] = htonl((2 << 30) | (rtp->send_payload << 16) | (rtp->seqno));

	/* Boom, send it on out */
	res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 4, 0, &remote_address);
	if (res < 0) {
		ast_log(LOG_ERROR, "RTP Transmission error to %s: %s\n",
			ast_sockaddr_stringify(&remote_address),
			strerror(errno));
	}

	if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Sent RTP DTMF packet to %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
			    ast_sockaddr_stringify(&remote_address),
			    rtp->send_payload, rtp->seqno, rtp->lastdigitts, res - hdrlen);
	}

	/* And now we increment some values for the next time we swing by */
	rtp->seqno++;
	rtp->send_duration += 160;

	return 0;
}

static int ast_rtp_dtmf_end_with_duration(struct ast_rtp_instance *instance, char digit, unsigned int duration)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int hdrlen = 12, res = 0, i = 0;
	char data[256];
	unsigned int *rtpheader = (unsigned int*)data;
	unsigned int measured_samples;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* Make sure we know where the remote side is so we can send them the packet we construct */
	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}

	/* Convert the given digit to the one we are going to send */
	if ((digit <= '9') && (digit >= '0')) {
		digit -= '0';
	} else if (digit == '*') {
		digit = 10;
	} else if (digit == '#') {
		digit = 11;
	} else if ((digit >= 'A') && (digit <= 'D')) {
		digit = digit - 'A' + 12;
	} else if ((digit >= 'a') && (digit <= 'd')) {
		digit = digit - 'a' + 12;
	} else {
		ast_log(LOG_WARNING, "Don't know how to represent '%c'\n", digit);
		return -1;
	}

	rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, 500000));

	if (duration > 0 && (measured_samples = duration * rtp_get_rate(rtp->f.subclass.codec) / 1000) > rtp->send_duration) {
		ast_debug(2, "Adjusting final end duration from %u to %u\n", rtp->send_duration, measured_samples);
		rtp->send_duration = measured_samples;
	}

	/* Construct the packet we are going to send */
	rtpheader[0] = htonl((2 << 30) | (1 << 23) | (rtp->send_payload << 16) | (rtp->seqno));
	rtpheader[1] = htonl(rtp->lastdigitts);
	rtpheader[2] = htonl(rtp->ssrc);
	rtpheader[3] = htonl((digit << 24) | (0xa << 16) | (rtp->send_duration));
	rtpheader[3] |= htonl((1 << 23));
	rtpheader[0] = htonl((2 << 30) | (rtp->send_payload << 16) | (rtp->seqno));

	/* Send it 3 times, that's the magical number */
	for (i = 0; i < 3; i++) {
		res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 4, 0, &remote_address);
		if (res < 0) {
			ast_log(LOG_ERROR, "RTP Transmission error to %s: %s\n",
				ast_sockaddr_stringify(&remote_address),
				strerror(errno));
		}
		if (rtp_debug_test_addr(&remote_address)) {
			ast_verbose("Sent RTP DTMF packet to %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
				    ast_sockaddr_stringify(&remote_address),
				    rtp->send_payload, rtp->seqno, rtp->lastdigitts, res - hdrlen);
		}
	}

	/* Oh and we can't forget to turn off the stuff that says we are sending DTMF */
	rtp->lastts += rtp->send_duration;
	rtp->sending_digit = 0;
	rtp->send_digit = 0;

	return 0;
}

static int ast_rtp_dtmf_end(struct ast_rtp_instance *instance, char digit)
{
	return ast_rtp_dtmf_end_with_duration(instance, digit, 0);
}

static void ast_rtp_update_source(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* We simply set this bit so that the next packet sent will have the marker bit turned on */
	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);
	ast_debug(3, "Setting the marker bit due to a source update\n");

	return;
}

static void ast_rtp_change_source(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_srtp *srtp = ast_rtp_instance_get_srtp(instance);
	unsigned int ssrc = ast_random();

	if (!rtp->lastts) {
		ast_debug(3, "Not changing SSRC since we haven't sent any RTP yet\n");
		return;
	}

	/* We simply set this bit so that the next packet sent will have the marker bit turned on */
	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);

	ast_debug(3, "Changing ssrc from %u to %u due to a source change\n", rtp->ssrc, ssrc);

	if (srtp) {
		ast_debug(3, "Changing ssrc for SRTP from %u to %u\n", rtp->ssrc, ssrc);
		res_srtp->change_source(srtp, rtp->ssrc, ssrc);
	}

	rtp->ssrc = ssrc;

	return;
}

static unsigned int calc_txstamp(struct ast_rtp *rtp, struct timeval *delivery)
{
	struct timeval t;
	long ms;

	if (ast_tvzero(rtp->txcore)) {
		rtp->txcore = ast_tvnow();
		rtp->txcore.tv_usec -= rtp->txcore.tv_usec % 20000;
	}

	t = (delivery && !ast_tvzero(*delivery)) ? *delivery : ast_tvnow();
	if ((ms = ast_tvdiff_ms(t, rtp->txcore)) < 0) {
		ms = 0;
	}
	rtp->txcore = t;

	return (unsigned int) ms;
}

static void timeval2ntp(struct timeval tv, unsigned int *msw, unsigned int *lsw)
{
	unsigned int sec, usec, frac;
	sec = tv.tv_sec + 2208988800u; /* Sec between 1900 and 1970 */
	usec = tv.tv_usec;
	frac = (usec << 12) + (usec << 8) - ((usec * 3650) >> 6);
	*msw = sec;
	*lsw = frac;
}

/*! \brief Send RTCP recipient's report */
static int ast_rtcp_write_rr(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int res;
	int len = 32;
	unsigned int lost;
	unsigned int extended;
	unsigned int expected;
	unsigned int expected_interval;
	unsigned int received_interval;
	int lost_interval;
	struct timeval now;
	unsigned int *rtcpheader;
	char bdata[1024];
	struct timeval dlsr;
	int fraction;
	int rate = rtp_get_rate(rtp->f.subclass.codec);

	double rxlost_current;

	if (!rtp || !rtp->rtcp)
		return 0;

	if (ast_sockaddr_isnull(&rtp->rtcp->them)) {
		/*
		 * RTCP was stopped.
		 */
		return 0;
	}

	extended = rtp->cycles + rtp->lastrxseqno;
	expected = extended - rtp->seedrxseqno + 1;
	lost = expected - rtp->rxcount;
	expected_interval = expected - rtp->rtcp->expected_prior;
	rtp->rtcp->expected_prior = expected;
	received_interval = rtp->rxcount - rtp->rtcp->received_prior;
	rtp->rtcp->received_prior = rtp->rxcount;
	lost_interval = expected_interval - received_interval;

	if (lost_interval <= 0)
		rtp->rtcp->rxlost = 0;
	else rtp->rtcp->rxlost = rtp->rtcp->rxlost;
	if (rtp->rtcp->rxlost_count == 0)
		rtp->rtcp->minrxlost = rtp->rtcp->rxlost;
	if (lost_interval < rtp->rtcp->minrxlost)
		rtp->rtcp->minrxlost = rtp->rtcp->rxlost;
	if (lost_interval > rtp->rtcp->maxrxlost)
		rtp->rtcp->maxrxlost = rtp->rtcp->rxlost;

	rxlost_current = normdev_compute(rtp->rtcp->normdev_rxlost, rtp->rtcp->rxlost, rtp->rtcp->rxlost_count);
	rtp->rtcp->stdev_rxlost = stddev_compute(rtp->rtcp->stdev_rxlost, rtp->rtcp->rxlost, rtp->rtcp->normdev_rxlost, rxlost_current, rtp->rtcp->rxlost_count);
	rtp->rtcp->normdev_rxlost = rxlost_current;
	rtp->rtcp->rxlost_count++;

	if (expected_interval == 0 || lost_interval <= 0)
		fraction = 0;
	else
		fraction = (lost_interval << 8) / expected_interval;
	gettimeofday(&now, NULL);
	timersub(&now, &rtp->rtcp->rxlsr, &dlsr);
	rtcpheader = (unsigned int *)bdata;
	rtcpheader[0] = htonl((2 << 30) | (1 << 24) | (RTCP_PT_RR << 16) | ((len/4)-1));
	rtcpheader[1] = htonl(rtp->ssrc);
	rtcpheader[2] = htonl(rtp->themssrc);
	rtcpheader[3] = htonl(((fraction & 0xff) << 24) | (lost & 0xffffff));
	rtcpheader[4] = htonl((rtp->cycles) | ((rtp->lastrxseqno & 0xffff)));
	rtcpheader[5] = htonl((unsigned int)(rtp->rxjitter * rate));
	rtcpheader[6] = htonl(rtp->rtcp->themrxlsr);
	rtcpheader[7] = htonl((((dlsr.tv_sec * 1000) + (dlsr.tv_usec / 1000)) * 65536) / 1000);

	/*! \note Insert SDES here. Probably should make SDES text equal to mimetypes[code].type (not subtype 'cos
	  it can change mid call, and SDES can't) */
	rtcpheader[len/4]     = htonl((2 << 30) | (1 << 24) | (RTCP_PT_SDES << 16) | 2);
	rtcpheader[(len/4)+1] = htonl(rtp->ssrc);               /* Our SSRC */
	rtcpheader[(len/4)+2] = htonl(0x01 << 24);              /* Empty for the moment */
	len += 12;

	res = rtcp_sendto(instance, (unsigned int *)rtcpheader, len, 0, &rtp->rtcp->them);

	if (res < 0) {
		ast_log(LOG_ERROR, "RTCP RR transmission error, rtcp halted: %s\n",strerror(errno));
		return 0;
	}

	rtp->rtcp->rr_count++;
	if (rtcp_debug_test_addr(&rtp->rtcp->them)) {
		ast_verbose("\n* Sending RTCP RR to %s\n"
			"  Our SSRC: %u\nTheir SSRC: %u\niFraction lost: %d\nCumulative loss: %u\n"
			"  IA jitter: %.4f\n"
			"  Their last SR: %u\n"
			    "  DLSR: %4.4f (sec)\n\n",
			    ast_sockaddr_stringify(&rtp->rtcp->them),
			    rtp->ssrc, rtp->themssrc, fraction, lost,
			    rtp->rxjitter,
			    rtp->rtcp->themrxlsr,
			    (double)(ntohl(rtcpheader[7])/65536.0));
	}

	return res;
}

/*! \brief Send RTCP sender's report */
static int ast_rtcp_write_sr(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int res;
	int len = 0;
	struct timeval now;
	unsigned int now_lsw;
	unsigned int now_msw;
	unsigned int *rtcpheader;
	unsigned int lost;
	unsigned int extended;
	unsigned int expected;
	unsigned int expected_interval;
	unsigned int received_interval;
	int lost_interval;
	int fraction;
	struct timeval dlsr;
	char bdata[512];
	int rate = rtp_get_rate(rtp->f.subclass.codec);

	if (!rtp || !rtp->rtcp)
		return 0;

	if (ast_sockaddr_isnull(&rtp->rtcp->them)) {  /* This'll stop rtcp for this rtp session */
		/*
		 * RTCP was stopped.
		 */
		return 0;
	}

	gettimeofday(&now, NULL);
	timeval2ntp(now, &now_msw, &now_lsw); /* fill thses ones in from utils.c*/
	rtcpheader = (unsigned int *)bdata;
	rtcpheader[1] = htonl(rtp->ssrc);               /* Our SSRC */
	rtcpheader[2] = htonl(now_msw);                 /* now, MSW. gettimeofday() + SEC_BETWEEN_1900_AND_1970*/
	rtcpheader[3] = htonl(now_lsw);                 /* now, LSW */
	rtcpheader[4] = htonl(rtp->lastts);             /* FIXME shouldn't be that, it should be now */
	rtcpheader[5] = htonl(rtp->txcount);            /* No. packets sent */
	rtcpheader[6] = htonl(rtp->txoctetcount);       /* No. bytes sent */
	len += 28;

	extended = rtp->cycles + rtp->lastrxseqno;
	expected = extended - rtp->seedrxseqno + 1;
	if (rtp->rxcount > expected)
		expected += rtp->rxcount - expected;
	lost = expected - rtp->rxcount;
	expected_interval = expected - rtp->rtcp->expected_prior;
	rtp->rtcp->expected_prior = expected;
	received_interval = rtp->rxcount - rtp->rtcp->received_prior;
	rtp->rtcp->received_prior = rtp->rxcount;
	lost_interval = expected_interval - received_interval;
	if (expected_interval == 0 || lost_interval <= 0)
		fraction = 0;
	else
		fraction = (lost_interval << 8) / expected_interval;
	timersub(&now, &rtp->rtcp->rxlsr, &dlsr);
	rtcpheader[7] = htonl(rtp->themssrc);
	rtcpheader[8] = htonl(((fraction & 0xff) << 24) | (lost & 0xffffff));
	rtcpheader[9] = htonl((rtp->cycles) | ((rtp->lastrxseqno & 0xffff)));
	rtcpheader[10] = htonl((unsigned int)(rtp->rxjitter * rate));
	rtcpheader[11] = htonl(rtp->rtcp->themrxlsr);
	rtcpheader[12] = htonl((((dlsr.tv_sec * 1000) + (dlsr.tv_usec / 1000)) * 65536) / 1000);
	len += 24;

	rtcpheader[0] = htonl((2 << 30) | (1 << 24) | (RTCP_PT_SR << 16) | ((len/4)-1));

	/* Insert SDES here. Probably should make SDES text equal to mimetypes[code].type (not subtype 'cos */
	/* it can change mid call, and SDES can't) */
	rtcpheader[len/4]     = htonl((2 << 30) | (1 << 24) | (RTCP_PT_SDES << 16) | 2);
	rtcpheader[(len/4)+1] = htonl(rtp->ssrc);               /* Our SSRC */
	rtcpheader[(len/4)+2] = htonl(0x01 << 24);                    /* Empty for the moment */
	len += 12;

	res = rtcp_sendto(instance, (unsigned int *)rtcpheader, len, 0, &rtp->rtcp->them);
	if (res < 0) {
		ast_log(LOG_ERROR, "RTCP SR transmission error to %s, rtcp halted %s\n",
			ast_sockaddr_stringify(&rtp->rtcp->them),
			strerror(errno));
		return 0;
	}

	/* FIXME Don't need to get a new one */
	gettimeofday(&rtp->rtcp->txlsr, NULL);
	rtp->rtcp->sr_count++;

	rtp->rtcp->lastsrtxcount = rtp->txcount;

	if (rtcp_debug_test_addr(&rtp->rtcp->them)) {
		ast_verbose("* Sent RTCP SR to %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
		ast_verbose("  Our SSRC: %u\n", rtp->ssrc);
		ast_verbose("  Sent(NTP): %u.%010u\n", (unsigned int)now.tv_sec, (unsigned int)now.tv_usec*4096);
		ast_verbose("  Sent(RTP): %u\n", rtp->lastts);
		ast_verbose("  Sent packets: %u\n", rtp->txcount);
		ast_verbose("  Sent octets: %u\n", rtp->txoctetcount);
		ast_verbose("  Report block:\n");
		ast_verbose("  Fraction lost: %u\n", fraction);
		ast_verbose("  Cumulative loss: %u\n", lost);
		ast_verbose("  IA jitter: %.4f\n", rtp->rxjitter);
		ast_verbose("  Their last SR: %u\n", rtp->rtcp->themrxlsr);
		ast_verbose("  DLSR: %4.4f (sec)\n\n", (double)(ntohl(rtcpheader[12])/65536.0));
	}
	manager_event(EVENT_FLAG_REPORTING, "RTCPSent", "To: %s\r\n"
					    "OurSSRC: %u\r\n"
					    "SentNTP: %u.%010u\r\n"
					    "SentRTP: %u\r\n"
					    "SentPackets: %u\r\n"
					    "SentOctets: %u\r\n"
					    "ReportBlock:\r\n"
					    "FractionLost: %u\r\n"
					    "CumulativeLoss: %u\r\n"
					    "IAJitter: %.4f\r\n"
					    "TheirLastSR: %u\r\n"
		      "DLSR: %4.4f (sec)\r\n",
		      ast_sockaddr_stringify(&rtp->rtcp->them),
		      rtp->ssrc,
		      (unsigned int)now.tv_sec, (unsigned int)now.tv_usec*4096,
		      rtp->lastts,
		      rtp->txcount,
		      rtp->txoctetcount,
		      fraction,
		      lost,
		      rtp->rxjitter,
		      rtp->rtcp->themrxlsr,
		      (double)(ntohl(rtcpheader[12])/65536.0));
	return res;
}

/*! \brief Write and RTCP packet to the far end
 * \note Decide if we are going to send an SR (with Reception Block) or RR
 * RR is sent if we have not sent any rtp packets in the previous interval */
static int ast_rtcp_write(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance *) data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int res;

	if (!rtp || !rtp->rtcp || rtp->rtcp->schedid == -1) {
		ao2_ref(instance, -1);
		return 0;
	}

	if (rtp->txcount > rtp->rtcp->lastsrtxcount) {
		res = ast_rtcp_write_sr(instance);
	} else {
		res = ast_rtcp_write_rr(instance);
	}

	if (!res) {
		/* 
		 * Not being rescheduled.
		 */
		ao2_ref(instance, -1);
		rtp->rtcp->schedid = -1;
	}

	return res;
}

static int ast_rtp_raw_write(struct ast_rtp_instance *instance, struct ast_frame *frame, int codec)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int pred, mark = 0;
	unsigned int *vts;	/* WebRTC BUNDLE: TX video timestamp clock selector (assigned in the video branch). */
	unsigned int ms = calc_txstamp(rtp, &frame->delivery);
	struct ast_sockaddr remote_address = { {0,} };
	int rate = rtp_get_rate(frame->subclass.codec) / 1000;

	if (frame->subclass.codec == AST_FORMAT_G722) {
		frame->samples /= 2;
	}

	if (rtp->sending_digit) {
		return 0;
	}

	if (frame->frametype == AST_FRAME_VOICE) {
		pred = rtp->lastts + frame->samples;

		/* Re-calculate last TS */
		rtp->lastts = rtp->lastts + ms * rate;
		if (ast_tvzero(frame->delivery)) {
			/* If this isn't an absolute delivery time, Check if it is close to our prediction,
			   and if so, go with our prediction */
			if (abs(rtp->lastts - pred) < MAX_TIMESTAMP_SKEW) {
				rtp->lastts = pred;
			} else {
				ast_debug(3, "Difference is %d, ms is %d\n", abs(rtp->lastts - pred), ms);
				mark = 1;
			}
		}
	} else if (frame->frametype == AST_FRAME_VIDEO) {
		/* WebRTC BUNDLE: run the video TX timestamp on a video-local clock (v_lastts) so interleaved video
		 * does not perturb the audio lastts clock. Non-bundle => vts == &rtp->lastts => byte-identical. */
		vts = rtp->bundle ? &rtp->v_lastts : &rtp->lastts;
		mark = frame->subclass.codec & 0x1;
		pred = rtp->lastovidtimestamp + frame->samples;
		/* Re-calculate last TS */
		*vts = *vts + ms * 90;
		/* If it's close to our prediction, go for it */
		if (ast_tvzero(frame->delivery)) {
			if (abs(*vts - pred) < 7200) {
				*vts = pred;
				rtp->lastovidtimestamp += frame->samples;
			} else {
				ast_debug(3, "Difference is %d, ms is %d (%d), pred/ts/samples %d/%d/%d\n", abs(*vts - pred), ms, ms * 90, *vts, pred, frame->samples);
				rtp->lastovidtimestamp = *vts;
			}
		}
	} else {
		pred = rtp->lastotexttimestamp + frame->samples;
		/* Re-calculate last TS */
		rtp->lastts = rtp->lastts + ms;
		/* If it's close to our prediction, go for it */
		if (ast_tvzero(frame->delivery)) {
			if (abs(rtp->lastts - pred) < 7200) {
				rtp->lastts = pred;
				rtp->lastotexttimestamp += frame->samples;
			} else {
				ast_debug(3, "Difference is %d, ms is %d, pred/ts/samples %d/%d/%d\n", abs(rtp->lastts - pred), ms, rtp->lastts, pred, frame->samples);
				rtp->lastotexttimestamp = rtp->lastts;
			}
		}
	}

	/* If we have been explicitly told to set the marker bit then do so */
	if (ast_test_flag(rtp, FLAG_NEED_MARKER_BIT)) {
		mark = 1;
		ast_clear_flag(rtp, FLAG_NEED_MARKER_BIT);
	}

	/* If the timestamp for non-digt packets has moved beyond the timestamp for digits, update the digit timestamp */
	if (rtp->lastts > rtp->lastdigitts) {
		rtp->lastdigitts = rtp->lastts;
	}

	if (ast_test_flag(frame, AST_FRFLAG_HAS_TIMING_INFO)) {
		rtp->lastts = frame->ts * rate;
	}

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* If we know the remote address construct a packet and send it out */
	if (!ast_sockaddr_isnull(&remote_address)) {
		int hdrlen = 12, res;
		unsigned char *rtpheader;
		/* WebRTC BUNDLE (RFC 8843): the bundled video sub-stream uses its OWN SSRC/seqno so the RTP egressing
		 * the shared transport is well-formed (a single SSRC must not mix payload types from different bundled
		 * m-sections). rtp->bundle==0 => audio path => byte-identical. */
		int tx_video = rtp->bundle && (frame->subclass.codec & AST_FORMAT_VIDEO_MASK);
		unsigned int tx_ssrc = tx_video ? rtp->v_ssrc : rtp->ssrc;
		unsigned short tx_seqno = tx_video ? rtp->v_seqno : rtp->seqno;
		unsigned int tx_ts = tx_video ? rtp->v_lastts : rtp->lastts;
		/* RFC 8843 §9 (MUST) / RFC 8285: stamp the one-byte MID header extension on every bundled WebRTC RTP
		 * packet so a strict max-bundle browser associates this SSRC with the correct m= line (a=ssrc/PT
		 * association alone is not honored). audio -> mid_value_audio, video -> mid_value_video. mid_ext_id==0
		 * (non-WebRTC / not negotiated) => no extension => byte-identical (rtpheader stays at data.ptr-12). */
		const char *tx_mid = NULL;
		int ext_bytes = 0, ext_words = 0, midlen = 0;

		if (rtp->mid_ext_id > 0) {
			tx_mid = tx_video ? rtp->mid_value_video : rtp->mid_value_audio;
			if (!ast_strlen_zero(tx_mid)) {
				midlen = strlen(tx_mid);
				ext_bytes = 4 + (((1 + midlen) + 3) & ~3);	/* 0xBEDE+len (4) + one-byte element padded to a 4-byte word */
				ext_words = (ext_bytes - 4) / 4;
			} else {
				tx_mid = NULL;
			}
		}

		hdrlen = 12 + ext_bytes;
		rtpheader = (unsigned char *)(frame->data.ptr - hdrlen);	/* headroom: AST_FRIENDLY_OFFSET(64) >= 12+ext */

		put_unaligned_uint32(rtpheader, htonl((2 << 30) | (tx_mid ? (1 << 28) : 0) | (codec << 16) | (tx_seqno) | (mark << 23)));
		put_unaligned_uint32(rtpheader + 4, htonl(tx_ts));
		put_unaligned_uint32(rtpheader + 8, htonl(tx_ssrc));
		if (tx_mid) {
			rtpheader[12] = 0xBE;	/* RFC 8285 one-byte header extension profile (0xBEDE) */
			rtpheader[13] = 0xDE;
			rtpheader[14] = (unsigned char)((ext_words >> 8) & 0xff);	/* length in 32-bit words */
			rtpheader[15] = (unsigned char)(ext_words & 0xff);
			rtpheader[16] = (unsigned char)((rtp->mid_ext_id << 4) | (midlen - 1));	/* element: id<<4 | (len-1) */
			memcpy(rtpheader + 17, tx_mid, midlen);
			if (ext_bytes - 4 - (1 + midlen) > 0) {
				memset(rtpheader + 17 + midlen, 0, ext_bytes - 4 - (1 + midlen));	/* zero the word padding */
			}
		}

		if ((res = rtp_sendto(instance, (void *)rtpheader, frame->datalen + hdrlen, 0, &remote_address)) < 0) {
			if (!ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT) || (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT) && (ast_test_flag(rtp, FLAG_NAT_ACTIVE) == FLAG_NAT_ACTIVE))) {
				ast_debug(1, "RTP Transmission error of packet %d to %s: %s\n",
					  rtp->seqno,
					  ast_sockaddr_stringify(&remote_address),
					  strerror(errno));
			} else if (((ast_test_flag(rtp, FLAG_NAT_ACTIVE) == FLAG_NAT_INACTIVE) || rtpdebug) && !ast_test_flag(rtp, FLAG_NAT_INACTIVE_NOWARN)) {
				/* Only give this error message once if we are not RTP debugging */
				if (option_debug || rtpdebug)
					ast_debug(0, "RTP NAT: Can't write RTP to private address %s, waiting for other end to send audio...\n",
						  ast_sockaddr_stringify(&remote_address));
				ast_set_flag(rtp, FLAG_NAT_INACTIVE_NOWARN);
			}
		} else {
			rtp->txcount++;
			rtp->txoctetcount += (res - hdrlen);

			if (rtp->rtcp && rtp->rtcp->schedid < 1) {
				ast_debug(1, "Starting RTCP transmission on RTP instance '%p'\n", instance);
				ao2_ref(instance, +1);
				rtp->rtcp->schedid = ast_sched_add(rtp->sched, ast_rtcp_calc_interval(rtp), ast_rtcp_write, instance);
				if (rtp->rtcp->schedid < 0) {
					ao2_ref(instance, -1);
					ast_log(LOG_WARNING, "scheduling RTCP transmission failed.\n");
				}
			}
		}

		if (rtp_debug_test_addr(&remote_address)) {
			ast_verbose("Sent RTP packet to      %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
				    ast_sockaddr_stringify(&remote_address),
				    codec, rtp->seqno, rtp->lastts, res - hdrlen);
		}
	}

	/* WebRTC BUNDLE: advance the sub-stream's own seqno (audio vs bundled video). */
	if (rtp->bundle && (frame->subclass.codec & AST_FORMAT_VIDEO_MASK)) {
		rtp->v_seqno++;
	} else {
		rtp->seqno++;
	}

	return 0;
}

static struct ast_frame *red_t140_to_red(struct rtp_red *red) {
	unsigned char *data = red->t140red.data.ptr;
	int len = 0;
	int i;

	/* replace most aged generation */
	if (red->len[0]) {
		for (i = 1; i < red->num_gen+1; i++)
			len += red->len[i];

		memmove(&data[red->hdrlen], &data[red->hdrlen+red->len[0]], len);
	}

	/* Store length of each generation and primary data length*/
	for (i = 0; i < red->num_gen; i++)
		red->len[i] = red->len[i+1];
	/* Promote the just-sent primary to the newest redundant generation. A redundant block's RFC 2198 length
	 * field is only 10 bits (max 1023); the PRIMARY block has no length field so it may be larger, but it
	 * cannot be carried as redundancy without wrapping the field mod 1024 and desyncing the receiver. Refuse
	 * to promote an oversized block (len 0 = no redundancy for it): it still went out as this packet's primary,
	 * it is simply not protected redundantly afterward. */
	red->len[i] = (red->t140.datalen > 1023) ? 0 : red->t140.datalen;

	/* Write each generation length into its RED block header as the RFC 2198 10-bit field
	 * (rfc2198.txt:247): the low 8 bits go in byte 3, the high 2 bits in the low 2 bits of byte 2
	 * (preserving byte 2's high 6 bits, which carry the timestamp offset). Accumulate the FULL length,
	 * not the truncated low byte, so the primary-data offset stays correct for blocks > 255 bytes. */
	len = red->hdrlen;
	for (i = 0; i < red->num_gen; i++) {
		data[i * 4 + 3] = red->len[i] & 0xFF;
		data[i * 4 + 2] = (data[i * 4 + 2] & 0xFC) | ((red->len[i] >> 8) & 0x03);
		len += red->len[i];
	}

	/* Belt-and-suspenders: the rtp_red_buffer cap should already keep len + datalen within t140red_data, but
	 * guard this output copy directly - drop fail-closed rather than overflow if anything ever diverged
	 * (len = hdrlen + carried redundancy; data == t140red_data[sizeof]). */
	if (red->t140.datalen > (int) sizeof(red->t140red_data) - len) {
		ast_log(LOG_WARNING, "RED T.140: output overflow guard (primary %d at offset %d > %zu); dropping packet\n",
			red->t140.datalen, len, sizeof(red->t140red_data));
		red->t140.datalen = 0;
		return NULL;
	}
	/* add primary data to buffer */
	memcpy(&data[len], red->t140.data.ptr, red->t140.datalen);
	red->t140red.datalen = len + red->t140.datalen;

	/* no primary data and no generations to send */
	if (len == red->hdrlen && !red->t140.datalen)
		return NULL;

	/* reset t.140 buffer */
	red->t140.datalen = 0;

	return &red->t140red;
}

static int ast_rtp_write(struct ast_rtp_instance *instance, struct ast_frame *frame)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	format_t codec, subclass;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* If we don't actually know the remote address don't even bother doing anything */
	if (ast_sockaddr_isnull(&remote_address)) {
		ast_debug(1, "No remote address on RTP instance '%p' so dropping frame\n", instance);
		return 0;
	}

	/* If there is no data length we can't very well send the packet */
	if (!frame->datalen) {
		ast_debug(1, "Received frame with no data for RTP instance '%p' so dropping frame\n", instance);
		return 0;
	}

	/* If the packet is not one our RTP stack supports bail out */
	if (frame->frametype != AST_FRAME_VOICE && frame->frametype != AST_FRAME_VIDEO && frame->frametype != AST_FRAME_TEXT) {
		ast_log(LOG_WARNING, "RTP can only send voice, video, and text\n");
		return -1;
	}

	if (rtp->red) {
		/* return 0; */
		/* no primary data or generations to send */
		if ((frame = red_t140_to_red(rtp->red)) == NULL)
			return 0;
	}

	/* Grab the subclass and look up the payload we are going to use */
	subclass = frame->subclass.codec;
	if (frame->frametype == AST_FRAME_VIDEO) {
		subclass &= ~0x1LL;
	}
	if ((codec = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(instance), 1, subclass)) < 0) {
		ast_log(LOG_WARNING, "Don't know how to send format %s packets with RTP\n", ast_getformatname(frame->subclass.codec));
		return -1;
	}

	/* Oh dear, if the format changed we will have to set up a new smoother */
	if (rtp->lasttxformat != subclass) {
		ast_debug(1, "Ooh, format changed from %s to %s\n", ast_getformatname(rtp->lasttxformat), ast_getformatname(subclass));
		rtp->lasttxformat = subclass;
		if (rtp->smoother) {
			ast_smoother_free(rtp->smoother);
			rtp->smoother = NULL;
		}
	}

	/* If no smoother is present see if we have to set one up */
	if (!rtp->smoother) {
		struct ast_format_list fmt = ast_codec_pref_getsize(&ast_rtp_instance_get_codecs(instance)->pref, subclass);

		switch (subclass) {
		case AST_FORMAT_SPEEX:
		case AST_FORMAT_SPEEX16:
		case AST_FORMAT_G723_1:
		case AST_FORMAT_SIREN7:
		case AST_FORMAT_SIREN14:
		case AST_FORMAT_G719:
		case AST_FORMAT_OPUS:
			/* these are all frame-based codecs and cannot be safely run through
			   a smoother. Opus is VBR: the default smoother (fr_len 960, frame.c:144) would
			   re-chunk its variable-size compressed packets into fixed 960-byte frames,
			   concatenating/splitting them — exactly the garbled "noise" on a both-Opus
			   WebRTC passthrough. opus->ulaw transcoded calls are unaffected (no raw Opus TX). */
			break;
		default:
			if (fmt.inc_ms) {
				if (!(rtp->smoother = ast_smoother_new((fmt.cur_ms * fmt.fr_len) / fmt.inc_ms))) {
					ast_log(LOG_WARNING, "Unable to create smoother: format %s ms: %d len: %d\n", ast_getformatname(subclass), fmt.cur_ms, ((fmt.cur_ms * fmt.fr_len) / fmt.inc_ms));
					return -1;
				}
				if (fmt.flags) {
					ast_smoother_set_flags(rtp->smoother, fmt.flags);
				}
				ast_debug(1, "Created smoother: format: %s ms: %d len: %d\n", ast_getformatname(subclass), fmt.cur_ms, ((fmt.cur_ms * fmt.fr_len) / fmt.inc_ms));
			}
		}
	}

	/* Feed audio frames into the actual function that will create a frame and send it */
	if (rtp->smoother) {
		struct ast_frame *f;

		if (ast_smoother_test_flag(rtp->smoother, AST_SMOOTHER_FLAG_BE)) {
			ast_smoother_feed_be(rtp->smoother, frame);
		} else {
			ast_smoother_feed(rtp->smoother, frame);
		}

		while ((f = ast_smoother_read(rtp->smoother)) && (f->data.ptr)) {
				ast_rtp_raw_write(instance, f, codec);
		}
	} else {
		int hdrlen = 12;
		struct ast_frame *f = NULL;

		if (frame->offset < hdrlen) {
			f = ast_frdup(frame);
		} else {
			f = frame;
		}
		if (f->data.ptr) {
			ast_rtp_raw_write(instance, f, codec);
		}
		if (f != frame) {
			ast_frfree(f);
		}

	}

	return 0;
}

static void calc_rxstamp(struct timeval *tv, struct ast_rtp *rtp, unsigned int timestamp, int mark)
{
	struct timeval now;
	struct timeval tmp;
	double transit;
	double current_time;
	double d;
	double dtv;
	double prog;
	int rate = rtp_get_rate(rtp->f.subclass.codec);

	double normdev_rxjitter_current;
	if ((!rtp->rxcore.tv_sec && !rtp->rxcore.tv_usec) || mark) {
		gettimeofday(&rtp->rxcore, NULL);
		rtp->drxcore = (double) rtp->rxcore.tv_sec + (double) rtp->rxcore.tv_usec / 1000000;
		/* map timestamp to a real time */
		rtp->seedrxts = timestamp; /* Their RTP timestamp started with this */
		tmp = ast_samp2tv(timestamp, rate);
		rtp->rxcore = ast_tvsub(rtp->rxcore, tmp);
		/* Round to 0.1ms for nice, pretty timestamps */
		rtp->rxcore.tv_usec -= rtp->rxcore.tv_usec % 100;
	}

	gettimeofday(&now,NULL);
	/* rxcore is the mapping between the RTP timestamp and _our_ real time from gettimeofday() */
	tmp = ast_samp2tv(timestamp, rate);
	*tv = ast_tvadd(rtp->rxcore, tmp);

	prog = (double)((timestamp-rtp->seedrxts)/(float)(rate));
	dtv = (double)rtp->drxcore + (double)(prog);
	current_time = (double)now.tv_sec + (double)now.tv_usec/1000000;
	transit = current_time - dtv;
	d = transit - rtp->rxtransit;
	rtp->rxtransit = transit;
	if (d<0)
		d=-d;
	rtp->rxjitter += (1./16.) * (d - rtp->rxjitter);

	if (rtp->rtcp) {
		if (rtp->rxjitter > rtp->rtcp->maxrxjitter)
			rtp->rtcp->maxrxjitter = rtp->rxjitter;
		if (rtp->rtcp->rxjitter_count == 1)
			rtp->rtcp->minrxjitter = rtp->rxjitter;
		if (rtp->rtcp && rtp->rxjitter < rtp->rtcp->minrxjitter)
			rtp->rtcp->minrxjitter = rtp->rxjitter;

		normdev_rxjitter_current = normdev_compute(rtp->rtcp->normdev_rxjitter,rtp->rxjitter,rtp->rtcp->rxjitter_count);
		rtp->rtcp->stdev_rxjitter = stddev_compute(rtp->rtcp->stdev_rxjitter,rtp->rxjitter,rtp->rtcp->normdev_rxjitter,normdev_rxjitter_current,rtp->rtcp->rxjitter_count);

		rtp->rtcp->normdev_rxjitter = normdev_rxjitter_current;
		rtp->rtcp->rxjitter_count++;
	}
}

static struct ast_frame *create_dtmf_frame(struct ast_rtp_instance *instance, enum ast_frame_type type, int compensate)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	if (((compensate && type == AST_FRAME_DTMF_END) || (type == AST_FRAME_DTMF_BEGIN)) && ast_tvcmp(ast_tvnow(), rtp->dtmfmute) < 0) {
		ast_debug(1, "Ignore potential DTMF echo from '%s'\n",
			  ast_sockaddr_stringify(&remote_address));
		rtp->resp = 0;
		rtp->dtmfsamples = 0;
		return &ast_null_frame;
	}
	ast_debug(1, "Sending dtmf: %d (%c), at %s\n", rtp->resp, rtp->resp,
		  ast_sockaddr_stringify(&remote_address));
	if (rtp->resp == 'X') {
		rtp->f.frametype = AST_FRAME_CONTROL;
		rtp->f.subclass.integer = AST_CONTROL_FLASH;
	} else {
		rtp->f.frametype = type;
		rtp->f.subclass.integer = rtp->resp;
	}
	rtp->f.datalen = 0;
	rtp->f.samples = 0;
	rtp->f.mallocd = 0;
	rtp->f.src = "RTP";
	AST_LIST_NEXT(&rtp->f, frame_list) = NULL;

	return &rtp->f;
}

/*! \brief Prepend \a count U+FFFD missing-text markers (3 bytes each) into a T.140 frame's leading
 * headroom (AST_FRIENDLY_OFFSET, frame.h:217) instead of tail-growing. A tail memmove on a max-size
 * (8192-byte) packet would write past rtp->rawdata into the following struct field. RFC 4103 §5.3
 * (rfc4103.txt:464-477) calls for one missing-text marker per missing T140block; the U+FFFD (EF BF BD)
 * byte sequence itself is the established convention (ITU-T T.140 Addendum 1), not specified by RFC
 * 4103. No-op when there is not enough headroom. */
static void rtp_t140_prepend_markers(struct ast_frame *f, int count)
{
	unsigned char *p;
	int need = count * 3;
	int i;

	if (count <= 0 || f->offset < need) {
		return;
	}
	f->data.ptr = (unsigned char *) f->data.ptr - need;
	f->offset -= need;
	f->datalen += need;
	p = f->data.ptr;
	for (i = 0; i < count; i++) {
		*p++ = 0xEF;
		*p++ = 0xBF;
		*p++ = 0xBD;
	}
}

static void process_dtmf_rfc2833(struct ast_rtp_instance *instance, unsigned char *data, int len, unsigned int seqno, unsigned int timestamp, struct ast_sockaddr *addr, int payloadtype, int mark, struct frame_list *frames)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	unsigned int event, event_end, samples;
	char resp = 0;
	struct ast_frame *f = NULL;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* RFC 4733 §2.3: the telephone-event payload is a fixed 4 octets; a shorter body would make the
	 * three ntohl() reads below run past the packet (mirrors the guard in process_dtmf_cisco). */
	if (len < 4) {
		return;
	}

	/* Figure out event, event end, and samples */
	event = ntohl(*((unsigned int *)(data)));
	event >>= 24;
	event_end = ntohl(*((unsigned int *)(data)));
	event_end <<= 8;
	event_end >>= 24;
	samples = ntohl(*((unsigned int *)(data)));
	samples &= 0xFFFF;

	if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Got  RTP RFC2833 from   %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u, mark %d, event %08x, end %d, duration %-5.5d) \n",
			    ast_sockaddr_stringify(&remote_address),
			    payloadtype, seqno, timestamp, len, (mark?1:0), event, ((event_end & 0x80)?1:0), samples);
	}

	/* Print out debug if turned on */
	if (rtpdebug || option_debug > 2)
		ast_debug(0, "- RTP 2833 Event: %08x (len = %d)\n", event, len);

	/* Figure out what digit was pressed */
	if (event < 10) {
		resp = '0' + event;
	} else if (event < 11) {
		resp = '*';
	} else if (event < 12) {
		resp = '#';
	} else if (event < 16) {
		resp = 'A' + (event - 12);
	} else if (event < 17) {        /* Event 16: Hook flash */
		resp = 'X';
	} else {
		/* Not a supported event */
		ast_log(LOG_DEBUG, "Ignoring RTP 2833 Event: %08x. Not a DTMF Digit.\n", event);
		return;
	}

	if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE)) {
		if ((rtp->lastevent != timestamp) || (rtp->resp && rtp->resp != resp)) {
			rtp->resp = resp;
			rtp->dtmf_timeout = 0;
			f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_END, ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE)));
			f->len = 0;
			rtp->lastevent = timestamp;
			AST_LIST_INSERT_TAIL(frames, f, frame_list);
		}
	} else {
		/*  The duration parameter measures the complete
		    duration of the event (from the beginning) - RFC2833.
		    Account for the fact that duration is only 16 bits long
		    (about 8 seconds at 8000 Hz) and can wrap is digit
		    is hold for too long. */
		unsigned int new_duration = rtp->dtmf_duration;
		unsigned int last_duration = new_duration & 0xFFFF;

		if (last_duration > 64000 && samples < last_duration) {
			new_duration += 0xFFFF + 1;
		}
		new_duration = (new_duration & ~0xFFFF) | samples;

		/* The second portion of this check is to not mistakenly
		 * stop accepting DTMF if the seqno rolls over beyond
		 * 65535.
		 */
		if (rtp->lastevent > seqno && rtp->lastevent - seqno < 50) {
			/* Out of order frame. Processing this can cause us to
			 * improperly duplicate incoming DTMF, so just drop
			 * this.
			 */
			return;
		}

		if (event_end & 0x80) {
			/* End event */
			if ((rtp->lastevent != seqno) && rtp->resp) {
				rtp->dtmf_duration = new_duration;
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_END, 0));
				f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.codec)), ast_tv(0, 0));
				rtp->resp = 0;
				rtp->dtmf_duration = rtp->dtmf_timeout = 0;
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
			}
		} else {
			/* Begin/continuation */

			if (rtp->resp && rtp->resp != resp) {
				/* Another digit already began. End it */
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_END, 0));
				f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.codec)), ast_tv(0, 0));
				rtp->resp = 0;
				rtp->dtmf_duration = rtp->dtmf_timeout = 0;
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
			}

			if (rtp->resp) {
				/* Digit continues */
				rtp->dtmf_duration = new_duration;
			} else {
				/* New digit began */
				rtp->resp = resp;
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_BEGIN, 0));
				rtp->dtmf_duration = samples;
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
			}

			rtp->dtmf_timeout = timestamp + rtp->dtmf_duration + dtmftimeout;
		}

		rtp->lastevent = seqno;
	}

	rtp->dtmfsamples = samples;

	return;
}

static struct ast_frame *process_dtmf_cisco(struct ast_rtp_instance *instance, unsigned char *data, int len, unsigned int seqno, unsigned int timestamp, struct ast_sockaddr *addr, int payloadtype, int mark)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	unsigned int event, flags, power;
	char resp = 0;
	unsigned char seq;
	struct ast_frame *f = NULL;

	if (len < 4) {
		return NULL;
	}

	/*      The format of Cisco RTP DTMF packet looks like next:
		+0                              - sequence number of DTMF RTP packet (begins from 1,
						  wrapped to 0)
		+1                              - set of flags
		+1 (bit 0)              - flaps by different DTMF digits delimited by audio
						  or repeated digit without audio???
		+2 (+4,+6,...)  - power level? (rises from 0 to 32 at begin of tone
						  then falls to 0 at its end)
		+3 (+5,+7,...)  - detected DTMF digit (0..9,*,#,A-D,...)
		Repeated DTMF information (bytes 4/5, 6/7) is history shifted right
		by each new packet and thus provides some redudancy.

		Sample of Cisco RTP DTMF packet is (all data in hex):
			19 07 00 02 12 02 20 02
		showing end of DTMF digit '2'.

		The packets
			27 07 00 02 0A 02 20 02
			28 06 20 02 00 02 0A 02
		shows begin of new digit '2' with very short pause (20 ms) after
		previous digit '2'. Bit +1.0 flips at begin of new digit.

		Cisco RTP DTMF packets comes as replacement of audio RTP packets
		so its uses the same sequencing and timestamping rules as replaced
		audio packets. Repeat interval of DTMF packets is 20 ms and not rely
		on audio framing parameters. Marker bit isn't used within stream of
		DTMFs nor audio stream coming immediately after DTMF stream. Timestamps
		are not sequential at borders between DTMF and audio streams,
	*/

	seq = data[0];
	flags = data[1];
	power = data[2];
	event = data[3] & 0x1f;

	if (option_debug > 2 || rtpdebug)
		ast_debug(0, "Cisco DTMF Digit: %02x (len=%d, seq=%d, flags=%02x, power=%d, history count=%d)\n", event, len, seq, flags, power, (len - 4) / 2);
	if (event < 10) {
		resp = '0' + event;
	} else if (event < 11) {
		resp = '*';
	} else if (event < 12) {
		resp = '#';
	} else if (event < 16) {
		resp = 'A' + (event - 12);
	} else if (event < 17) {
		resp = 'X';
	}
	if ((!rtp->resp && power) || (rtp->resp && (rtp->resp != resp))) {
		rtp->resp = resp;
		/* Why we should care on DTMF compensation at reception? */
		if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE)) {
			f = create_dtmf_frame(instance, AST_FRAME_DTMF_BEGIN, 0);
			rtp->dtmfsamples = 0;
		}
	} else if ((rtp->resp == resp) && !power) {
		f = create_dtmf_frame(instance, AST_FRAME_DTMF_END, ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE));
		f->samples = rtp->dtmfsamples * (rtp->lastrxformat ? (rtp_get_rate(rtp->lastrxformat) / 1000) : 8);
		rtp->resp = 0;
	} else if (rtp->resp == resp)
		rtp->dtmfsamples += 20 * (rtp->lastrxformat ? (rtp_get_rate(rtp->lastrxformat) / 1000) : 8);

	rtp->dtmf_timeout = 0;

	return f;
}

static struct ast_frame *process_cn_rfc3389(struct ast_rtp_instance *instance, unsigned char *data, int len, unsigned int seqno, unsigned int timestamp, struct ast_sockaddr *addr, int payloadtype, int mark)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* Convert comfort noise into audio with various codecs.  Unfortunately this doesn't
	   totally help us out becuase we don't have an engine to keep it going and we are not
	   guaranteed to have it every 20ms or anything */
	if (rtpdebug)
		ast_debug(0, "- RTP 3389 Comfort noise event: Level %" PRId64 " (len = %d)\n", rtp->lastrxformat, len);

	if (ast_test_flag(rtp, FLAG_3389_WARNING)) {
		struct ast_sockaddr remote_address = { {0,} };

		ast_rtp_instance_get_remote_address(instance, &remote_address);

		ast_log(LOG_NOTICE, "Comfort noise support incomplete in GABpbx (RFC 3389). Please turn off on client if possible. Client address: %s\n",
			ast_sockaddr_stringify(&remote_address));
		ast_set_flag(rtp, FLAG_3389_WARNING);
	}

	/* Must have at least one byte */
	if (!len)
		return NULL;
	if (len < 24) {
		rtp->f.data.ptr = rtp->rawdata + AST_FRIENDLY_OFFSET;
		rtp->f.datalen = len - 1;
		rtp->f.offset = AST_FRIENDLY_OFFSET;
		memcpy(rtp->f.data.ptr, data + 1, len - 1);
	} else {
		rtp->f.data.ptr = NULL;
		rtp->f.offset = 0;
		rtp->f.datalen = 0;
	}
	rtp->f.frametype = AST_FRAME_CNG;
	rtp->f.subclass.integer = data[0] & 0x7f;
	rtp->f.samples = 0;
	rtp->f.delivery.tv_usec = rtp->f.delivery.tv_sec = 0;

	return &rtp->f;
}

static struct ast_frame *ast_rtcp_read(struct ast_rtp_instance *instance)
{
	struct ast_sockaddr addr;
	unsigned int rtcpdata[8192 + AST_FRIENDLY_OFFSET];
	unsigned int *rtcpheader = (unsigned int *)(rtcpdata + AST_FRIENDLY_OFFSET);
	int res;

	/* Read in RTCP data from the socket */
	if ((res = rtcp_recvfrom(instance, rtcpdata + AST_FRIENDLY_OFFSET,
				sizeof(rtcpdata) - sizeof(unsigned int) * AST_FRIENDLY_OFFSET,
				0, &addr)) < 0) {
		ast_assert(errno != EBADF);
		if (errno == EAGAIN) {
			return &ast_null_frame;
		}
#ifdef HAVE_OPENSSL
		{
			struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
			/* Same transient-ICMP tolerance as the RTP path: an ICMP unreachable (EIO/ECONNREFUSED/
			 * EHOSTUNREACH/ENETUNREACH) on a WebRTC/DTLS leg's RTCP socket is a bounced datagram during
			 * ICE probing, not a reason to hang up. rtptimeout still catches truly dead media. */
			if (rtp && rtp->dtls.ssl && (errno == EIO || errno == ECONNREFUSED
					|| errno == EHOSTUNREACH || errno == ENETUNREACH)) {
				ast_debug(1, "%p -- transient RTCP read error (%s) on a WebRTC/DTLS leg; ignoring\n",
					rtp, strerror(errno));
				return &ast_null_frame;
			}
		}
#endif
		ast_log(LOG_WARNING, "RTCP Read error: %s.  Hanging up.\n", strerror(errno));
		return NULL;
	}

	return ast_rtcp_interpret(instance, rtcpheader, res, &addr);
}

/*!
 * \brief Parse and process one (already-received, cleartext) RTCP datagram.
 *
 * The packet parsing/stats accounting that used to live inside ast_rtcp_read was split out here so it
 * can be driven from two callers with byte-identical behaviour:
 *   1. ast_rtcp_read() — the classic standalone-RTCP-socket path (plain RTP/RTCP, unchanged).
 *   2. the WebRTC rtcp-mux demux in __rtp_recvfrom() — muxed (S)RTCP that arrived on the RTP socket and
 *      has already been SRTCP-unprotected in place (RFC 5761). Before this split the muxed class was
 *      silently dropped, so a WebRTC leg never processed remote SR/RR (ast_rtp_get_stat starved) nor an
 *      inbound RTCP BYE. Feeding the unprotected buffer here reuses the exact same parser.
 *
 * \param instance   the RTP instance (caller holds whatever lock the original caller held)
 * \param rtcpheader pointer to the start of the cleartext RTCP compound packet
 * \param res        its length in bytes
 * \param addr       the source address of the datagram
 */
static struct ast_frame *ast_rtcp_interpret(struct ast_rtp_instance *instance, unsigned int *rtcpheader, int res, struct ast_sockaddr *addrp)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr addr = *addrp;
	int packetwords, position = 0;
	struct ast_frame *f = &ast_null_frame;

	packetwords = res / 4;

	if (res & 3) {
		/* RTCP packets are 32-bit word aligned (RFC 3550 §6.4); a non-aligned datagram is malformed. */
		if (option_debug || rtpdebug)
			ast_log(LOG_DEBUG, "RTCP not 32-bit aligned (%d bytes), dropping\n", res);
		return &ast_null_frame;
	}

	if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT)) {
		/* Send to whoever sent to us */
		if (ast_sockaddr_cmp(&rtp->rtcp->them, &addr)) {
			ast_sockaddr_copy(&rtp->rtcp->them, &addr);
			if (option_debug || rtpdebug)
				ast_debug(0, "RTCP NAT: Got RTCP from other end. Now sending to address %s\n",
					  ast_sockaddr_stringify(&rtp->rtcp->them));
		}
	}

	ast_debug(1, "Got RTCP report of %d bytes\n", res);

	while (position < packetwords) {
		int i, pt, rc;
		unsigned int length, dlsr, lsr, msw, lsw, comp;
		struct timeval now;
		double rttsec, reported_jitter, reported_normdev_jitter_current, normdevrtt_current, reported_lost, reported_normdev_lost_current;
		uint64_t rtt = 0;

		i = position;
		length = ntohl(rtcpheader[i]);
		pt = (length & 0xff0000) >> 16;
		rc = (length & 0x1f000000) >> 24;
		length &= 0xffff;

		/* RFC 3550 §6.4.1: the length field is the packet size in 32-bit words MINUS ONE (including the
		 * header word), so the packet spans words [position, position+length] and the next one starts at
		 * position+length+1 — that boundary must fit the datagram. length<1 is malformed (no SSRC). */
		if (length < 1 || (position + length + 1) > packetwords) {
			if (option_debug || rtpdebug)
				ast_log(LOG_DEBUG, "RTCP Read too short\n");
			return &ast_null_frame;
		}

		/* Per-type structural length: the declared length MUST cover the rc reception report blocks
		 * (6 words each, RFC 3550 §6.4) that the SR/RR paths below dereference. Without this a small
		 * length with rc>=1 reads report-block words past the packet — an uninitialised-stack / OOB
		 * read leaked via the RTCPReceived AMI event. SR = header+ssrc+5 sender-info + 6*rc words;
		 * RR = header+ssrc + 6*rc words; length is words-1. */
		if (pt == RTCP_PT_SR && length < (unsigned int) (6 + 6 * rc)) {
			if (option_debug || rtpdebug)
				ast_log(LOG_DEBUG, "RTCP SR length %u too short for rc=%d\n", length, rc);
			return &ast_null_frame;
		}
		if (pt == RTCP_PT_RR && length < (unsigned int) (1 + 6 * rc)) {
			if (option_debug || rtpdebug)
				ast_log(LOG_DEBUG, "RTCP RR length %u too short for rc=%d\n", length, rc);
			return &ast_null_frame;
		}

		if (rtcp_debug_test_addr(&addr)) {
			ast_verbose("\n\nGot RTCP from %s\n",
				    ast_sockaddr_stringify(&addr));
			ast_verbose("PT: %d(%s)\n", pt, (pt == 200) ? "Sender Report" : (pt == 201) ? "Receiver Report" : (pt == 192) ? "H.261 FUR" : "Unknown");
			ast_verbose("Reception reports: %d\n", rc);
			ast_verbose("SSRC of sender: %u\n", rtcpheader[i + 1]);
		}

		i += 2; /* Advance past header and ssrc */
		if (rc == 0 && pt == RTCP_PT_RR) {      /* We're receiving a receiver report with no reports, which is ok */
			position += (length + 1);
			continue;
		}

		switch (pt) {
		case RTCP_PT_SR:
			gettimeofday(&rtp->rtcp->rxlsr,NULL); /* To be able to populate the dlsr */
			rtp->rtcp->spc = ntohl(rtcpheader[i+3]);
			rtp->rtcp->soc = ntohl(rtcpheader[i + 4]);
			rtp->rtcp->themrxlsr = ((ntohl(rtcpheader[i]) & 0x0000ffff) << 16) | ((ntohl(rtcpheader[i + 1]) & 0xffff0000) >> 16); /* Going to LSR in RR*/

			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("NTP timestamp: %lu.%010lu\n", (unsigned long) ntohl(rtcpheader[i]), (unsigned long) ntohl(rtcpheader[i + 1]) * 4096);
				ast_verbose("RTP timestamp: %lu\n", (unsigned long) ntohl(rtcpheader[i + 2]));
				ast_verbose("SPC: %lu\tSOC: %lu\n", (unsigned long) ntohl(rtcpheader[i + 3]), (unsigned long) ntohl(rtcpheader[i + 4]));
			}
			i += 5;
			if (rc < 1)
				break;
			/* Intentional fall through */
		case RTCP_PT_RR:
			/* Don't handle multiple reception reports (rc > 1) yet */
			/* Calculate RTT per RFC */
			gettimeofday(&now, NULL);
			timeval2ntp(now, &msw, &lsw);
			if (ntohl(rtcpheader[i + 4]) && ntohl(rtcpheader[i + 5])) { /* We must have the LSR && DLSR */
				comp = ((msw & 0xffff) << 16) | ((lsw & 0xffff0000) >> 16);
				lsr = ntohl(rtcpheader[i + 4]);
				dlsr = ntohl(rtcpheader[i + 5]);
				rtt = comp - lsr - dlsr;

				/* Convert end to end delay to usec (keeping the calculation in 64bit space)
				   sess->ee_delay = (eedelay * 1000) / 65536; */
				if (rtt < 4294) {
					rtt = (rtt * 1000000) >> 16;
				} else {
					rtt = (rtt * 1000) >> 16;
					rtt *= 1000;
				}
				rtt = rtt / 1000.;
				rttsec = rtt / 1000.;
				rtp->rtcp->rtt = rttsec;

				if (comp - dlsr >= lsr) {
					rtp->rtcp->accumulated_transit += rttsec;

					if (rtp->rtcp->rtt_count == 0)
						rtp->rtcp->minrtt = rttsec;

					if (rtp->rtcp->maxrtt<rttsec)
						rtp->rtcp->maxrtt = rttsec;
					if (rtp->rtcp->minrtt>rttsec)
						rtp->rtcp->minrtt = rttsec;

					normdevrtt_current = normdev_compute(rtp->rtcp->normdevrtt, rttsec, rtp->rtcp->rtt_count);

					rtp->rtcp->stdevrtt = stddev_compute(rtp->rtcp->stdevrtt, rttsec, rtp->rtcp->normdevrtt, normdevrtt_current, rtp->rtcp->rtt_count);

					rtp->rtcp->normdevrtt = normdevrtt_current;

					rtp->rtcp->rtt_count++;
				} else if (rtcp_debug_test_addr(&addr)) {
					ast_verbose("Internal RTCP NTP clock skew detected: "
							   "lsr=%u, now=%u, dlsr=%u (%d:%03dms), "
						    "diff=%d\n",
						    lsr, comp, dlsr, dlsr / 65536,
						    (dlsr % 65536) * 1000 / 65536,
						    dlsr - (comp - lsr));
				}
			}

			rtp->rtcp->reported_jitter = ntohl(rtcpheader[i + 3]);
			reported_jitter = (double) rtp->rtcp->reported_jitter;

			if (rtp->rtcp->reported_jitter_count == 0)
				rtp->rtcp->reported_minjitter = reported_jitter;

			if (reported_jitter < rtp->rtcp->reported_minjitter)
				rtp->rtcp->reported_minjitter = reported_jitter;

			if (reported_jitter > rtp->rtcp->reported_maxjitter)
				rtp->rtcp->reported_maxjitter = reported_jitter;

			reported_normdev_jitter_current = normdev_compute(rtp->rtcp->reported_normdev_jitter, reported_jitter, rtp->rtcp->reported_jitter_count);

			rtp->rtcp->reported_stdev_jitter = stddev_compute(rtp->rtcp->reported_stdev_jitter, reported_jitter, rtp->rtcp->reported_normdev_jitter, reported_normdev_jitter_current, rtp->rtcp->reported_jitter_count);

			rtp->rtcp->reported_normdev_jitter = reported_normdev_jitter_current;

			rtp->rtcp->reported_lost = ntohl(rtcpheader[i + 1]) & 0xffffff;

			reported_lost = (double) rtp->rtcp->reported_lost;

			/* using same counter as for jitter */
			if (rtp->rtcp->reported_jitter_count == 0)
				rtp->rtcp->reported_minlost = reported_lost;

			if (reported_lost < rtp->rtcp->reported_minlost)
				rtp->rtcp->reported_minlost = reported_lost;

			if (reported_lost > rtp->rtcp->reported_maxlost)
				rtp->rtcp->reported_maxlost = reported_lost;
			reported_normdev_lost_current = normdev_compute(rtp->rtcp->reported_normdev_lost, reported_lost, rtp->rtcp->reported_jitter_count);

			rtp->rtcp->reported_stdev_lost = stddev_compute(rtp->rtcp->reported_stdev_lost, reported_lost, rtp->rtcp->reported_normdev_lost, reported_normdev_lost_current, rtp->rtcp->reported_jitter_count);

			rtp->rtcp->reported_normdev_lost = reported_normdev_lost_current;

			rtp->rtcp->reported_jitter_count++;

			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("  Fraction lost: %ld\n", (((long) ntohl(rtcpheader[i + 1]) & 0xff000000) >> 24));
				ast_verbose("  Packets lost so far: %d\n", rtp->rtcp->reported_lost);
				ast_verbose("  Highest sequence number: %ld\n", (long) (ntohl(rtcpheader[i + 2]) & 0xffff));
				ast_verbose("  Sequence number cycles: %ld\n", (long) (ntohl(rtcpheader[i + 2])) >> 16);
				ast_verbose("  Interarrival jitter: %u\n", rtp->rtcp->reported_jitter);
				ast_verbose("  Last SR(our NTP): %lu.%010lu\n",(unsigned long) ntohl(rtcpheader[i + 4]) >> 16,((unsigned long) ntohl(rtcpheader[i + 4]) << 16) * 4096);
				ast_verbose("  DLSR: %4.4f (sec)\n",ntohl(rtcpheader[i + 5])/65536.0);
				if (rtt)
					ast_verbose("  RTT: %lu(sec)\n", (unsigned long) rtt);
			}
			if (rtt) {
				manager_event(EVENT_FLAG_REPORTING, "RTCPReceived", "From: %s\r\n"
								    "PT: %d(%s)\r\n"
								    "ReceptionReports: %d\r\n"
								    "SenderSSRC: %u\r\n"
								    "FractionLost: %ld\r\n"
								    "PacketsLost: %d\r\n"
								    "HighestSequence: %ld\r\n"
								    "SequenceNumberCycles: %ld\r\n"
								    "IAJitter: %u\r\n"
								    "LastSR: %lu.%010lu\r\n"
								    "DLSR: %4.4f(sec)\r\n"
					      "RTT: %llu(sec)\r\n",
					      ast_sockaddr_stringify(&addr),
					      pt, (pt == 200) ? "Sender Report" : (pt == 201) ? "Receiver Report" : (pt == 192) ? "H.261 FUR" : "Unknown",
					      rc,
					      rtcpheader[i + 1],
					      (((long) ntohl(rtcpheader[i + 1]) & 0xff000000) >> 24),
					      rtp->rtcp->reported_lost,
					      (long) (ntohl(rtcpheader[i + 2]) & 0xffff),
					      (long) (ntohl(rtcpheader[i + 2])) >> 16,
					      rtp->rtcp->reported_jitter,
					      (unsigned long) ntohl(rtcpheader[i + 4]) >> 16, ((unsigned long) ntohl(rtcpheader[i + 4]) << 16) * 4096,
					      ntohl(rtcpheader[i + 5])/65536.0,
					      (unsigned long long)rtt);
			} else {
				manager_event(EVENT_FLAG_REPORTING, "RTCPReceived", "From: %s\r\n"
								    "PT: %d(%s)\r\n"
								    "ReceptionReports: %d\r\n"
								    "SenderSSRC: %u\r\n"
								    "FractionLost: %ld\r\n"
								    "PacketsLost: %d\r\n"
								    "HighestSequence: %ld\r\n"
								    "SequenceNumberCycles: %ld\r\n"
								    "IAJitter: %u\r\n"
								    "LastSR: %lu.%010lu\r\n"
					      "DLSR: %4.4f(sec)\r\n",
					      ast_sockaddr_stringify(&addr),
					      pt, (pt == 200) ? "Sender Report" : (pt == 201) ? "Receiver Report" : (pt == 192) ? "H.261 FUR" : "Unknown",
					      rc,
					      rtcpheader[i + 1],
					      (((long) ntohl(rtcpheader[i + 1]) & 0xff000000) >> 24),
					      rtp->rtcp->reported_lost,
					      (long) (ntohl(rtcpheader[i + 2]) & 0xffff),
					      (long) (ntohl(rtcpheader[i + 2])) >> 16,
					      rtp->rtcp->reported_jitter,
					      (unsigned long) ntohl(rtcpheader[i + 4]) >> 16,
					      ((unsigned long) ntohl(rtcpheader[i + 4]) << 16) * 4096,
					      ntohl(rtcpheader[i + 5])/65536.0);
			}
			break;
		case RTCP_PT_FUR:
			if (rtcp_debug_test_addr(&addr))
				ast_verbose("Received an RTCP Fast Update Request\n");
			rtp->f.frametype = AST_FRAME_CONTROL;
			rtp->f.subclass.integer = AST_CONTROL_VIDUPDATE;
			rtp->f.datalen = 0;
			rtp->f.samples = 0;
			rtp->f.mallocd = 0;
			rtp->f.src = "RTP";
			f = &rtp->f;
			break;
		case RTCP_PT_SDES:
			if (rtcp_debug_test_addr(&addr))
				ast_verbose("Received an SDES from %s\n",
					    ast_sockaddr_stringify(&rtp->rtcp->them));
			break;
		case RTCP_PT_BYE:
			if (rtcp_debug_test_addr(&addr))
				ast_verbose("Received a BYE from %s\n",
					    ast_sockaddr_stringify(&rtp->rtcp->them));
			break;
		default:
			ast_debug(1, "Unknown RTCP packet (pt=%d) received from %s\n",
				  pt, ast_sockaddr_stringify(&rtp->rtcp->them));
			break;
		}
		position += (length + 1);
	}

	rtp->rtcp->rtcp_info = 1;

	return f;
}

static int bridge_p2p_rtp_write(struct ast_rtp_instance *instance, unsigned int *rtpheader, int len, int hdrlen)
{
	struct ast_rtp_instance *instance1 = ast_rtp_instance_get_bridged(instance);
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance), *bridged = ast_rtp_instance_get_data(instance1);
	int res = 0, payload = 0, bridged_payload = 0, mark;
	struct ast_rtp_payload_type payload_type;
	int reconstruct = ntohl(rtpheader[0]);
	struct ast_sockaddr remote_address = { {0,} };
	unsigned int seqno, prev_seqno;

	/* Get fields from packet */
	payload = (reconstruct & 0x7f0000) >> 16;
	mark = (((reconstruct & 0x800000) >> 23) != 0);
	seqno = reconstruct & 0xffff;
	prev_seqno = rtp->lastrxseqno;
        rtp->lastrxseqno = seqno;

	/* Check what the payload value should be */
	payload_type = ast_rtp_codecs_payload_lookup(ast_rtp_instance_get_codecs(instance), payload);

	/* Otherwise adjust bridged payload to match */
	bridged_payload = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(instance1), payload_type.gabpbx_format, payload_type.code);

	/* If no codec could be matched between instance and instance1, then somehow things were made incompatible while we were still bridged.  Bail. */
	if (bridged_payload < 0) {
		return -1;
	}

	/* If the payload coming in is not one of the negotiated ones then send it to the core, this will cause formats to change and the bridge to break */
	if (!(ast_rtp_instance_get_codecs(instance1)->payloads[bridged_payload].code)) {
		return -1;
	}

	/* If the marker bit has been explicitly set turn it on */
	if (ast_test_flag(rtp, FLAG_NEED_MARKER_BIT)) {
		mark = 1;
		ast_clear_flag(rtp, FLAG_NEED_MARKER_BIT);
	}

	/* Reconstruct part of the packet */
	reconstruct &= 0xFF80FFFF;
	reconstruct |= (bridged_payload << 16);
	reconstruct |= (mark << 23);
	rtpheader[0] = htonl(reconstruct);

	ast_rtp_instance_get_remote_address(instance1, &remote_address);

	if (ast_sockaddr_isnull(&remote_address)) {
		ast_debug(1, "Remote address is null, most likely RTP has been stopped\n");
		return 0;
	}

	/* Send the packet back out */
	res = rtp_sendto(instance1, (void *)rtpheader, len, 0, &remote_address);
	if (res < 0) {
		if (!ast_rtp_instance_get_prop(instance1, AST_RTP_PROPERTY_NAT) || (ast_rtp_instance_get_prop(instance1, AST_RTP_PROPERTY_NAT) && (ast_test_flag(bridged, FLAG_NAT_ACTIVE) == FLAG_NAT_ACTIVE))) {
			ast_log(LOG_WARNING,
				"RTP Transmission error of packet to %s: %s\n",
				ast_sockaddr_stringify(&remote_address),
				strerror(errno));
		} else if (((ast_test_flag(bridged, FLAG_NAT_ACTIVE) == FLAG_NAT_INACTIVE) || rtpdebug) && !ast_test_flag(bridged, FLAG_NAT_INACTIVE_NOWARN)) {
			if (option_debug || rtpdebug)
				ast_log(LOG_WARNING,
					"RTP NAT: Can't write RTP to private "
					"address %s, waiting for other end to "
					"send audio...\n",
					ast_sockaddr_stringify(&remote_address));
			ast_set_flag(bridged, FLAG_NAT_INACTIVE_NOWARN);
		}
		return 0;
	} else if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Sent RTP P2P packet to %s (type %-2.2d, len %-6.6u)\n",
			    ast_sockaddr_stringify(&remote_address),
			    bridged_payload, len - hdrlen);
	}

	return 0;
}

static struct ast_frame *ast_rtp_read(struct ast_rtp_instance *instance, int rtcp)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr addr;
	int res, hdrlen = 12, version, payloadtype, padding, mark, ext, cc, prev_seqno;
	unsigned int *rtpheader = (unsigned int*)(rtp->rawdata + AST_FRIENDLY_OFFSET), seqno, ssrc, timestamp;
	struct ast_rtp_payload_type payload;
	struct ast_sockaddr remote_address = { {0,} };
	struct frame_list frames;
	/* WebRTC BUNDLE (RFC 8843): per-sub-stream RX routing, resolved after the SSRC is parsed below. */
	int is_video = 0;
	unsigned int *bundle_rxssrc, *bundle_rxcount, *bundle_cycles;
	int *bundle_lastrxseqno;
	unsigned short *bundle_seedrxseqno;

	/* If this is actually RTCP let's hop on over and handle it */
	if (rtcp) {
		if (rtp->rtcp) {
			return ast_rtcp_read(instance);
		}
		return &ast_null_frame;
	}

	/* If we are currently sending DTMF to the remote party send a continuation packet */
	if (rtp->sending_digit) {
		ast_rtp_dtmf_continuation(instance);
	}

	/* Actually read in the data from the socket */
	if ((res = rtp_recvfrom(instance, rtp->rawdata + AST_FRIENDLY_OFFSET,
				sizeof(rtp->rawdata) - AST_FRIENDLY_OFFSET, 0,
				&addr)) < 0) {
		ast_assert(errno != EBADF);
		if (errno == EAGAIN) {
			return &ast_null_frame;
		}
#ifdef HAVE_OPENSSL
		/* A transient ICMP port/host/net-unreachable (surfaced as EIO/ECONNREFUSED/EHOSTUNREACH/
		 * ENETUNREACH on the next recv) is NORMAL on a WebRTC/DTLS leg: while ICE is still probing, or
		 * if the browser momentarily stops listening on a candidate, our datagram bounces. Tearing the
		 * whole call down for it caused "cancel on answer" when a WebRTC browser is the CALLER (media
		 * setup on the caller leg races ICE). Ignore it — ICE re-latches, and rtptimeout still catches
		 * genuinely dead media. Plain (non-DTLS) RTP keeps the original hang-up. */
		if (rtp->dtls.ssl && (errno == EIO || errno == ECONNREFUSED
				|| errno == EHOSTUNREACH || errno == ENETUNREACH)) {
			ast_debug(1, "%p -- transient RTP read error (%s) on a WebRTC/DTLS leg; ignoring\n",
				rtp, strerror(errno));
			return &ast_null_frame;
		}
#endif
		ast_log(LOG_WARNING, "RTP Read error: %s. Hanging up.\n", strerror(errno));
		return NULL;
	}

	/* Make sure the data that was read in is actually enough to make up an RTP packet */
	if (res < hdrlen) {
		ast_log(LOG_WARNING, "RTP Read too short\n");
		return &ast_null_frame;
	}

	/* If strict RTP protection is enabled see if we need to learn the remote address or if we need to drop the packet */
	if (rtp->strict_rtp_state == STRICT_RTP_LEARN) {
		ast_debug(1, "%p -- start learning mode pass with addr = %s\n", rtp, ast_sockaddr_stringify(&addr));
		/* For now, we always copy the address. */
		ast_sockaddr_copy(&rtp->strict_rtp_address, &addr);

		/* Send the rtp and the seqno from header to rtp_learning_rtp_seq_update to see whether we can exit or not.
		 * WebRTC BUNDLE: audio+video have independent RTP sequence spaces on one socket, so this single-sequence
		 * probation would be disturbed by interleaving and could drop valid audio. ICE + DTLS-SRTP + the source
		 * address already authenticate the 5-tuple, so skip the seqno probation and close immediately. */
		if (!rtp->bundle && rtp_learning_rtp_seq_update(rtp, ntohl(rtpheader[0]))) {
			ast_debug(1, "%p -- Condition for learning hasn't exited, so reject the frame.\n", rtp);
			return &ast_null_frame;
		}

		ast_debug(1, "%p -- Probation Ended. Set strict_rtp_state to STRICT_RTP_CLOSED with address %s\n", rtp, ast_sockaddr_stringify(&addr));
		rtp->strict_rtp_state = STRICT_RTP_CLOSED;
	} else if (rtp->strict_rtp_state == STRICT_RTP_CLOSED) {
		if (ast_sockaddr_cmp(&rtp->strict_rtp_address, &addr)) {
			/* Hmm, not the strict addres. Perhaps we're getting audio from the alternate? */
			if (!ast_sockaddr_cmp(&rtp->alt_rtp_address, &addr)) {
				/* ooh, we did! You're now the new expected address, son! */
				ast_sockaddr_copy(&rtp->strict_rtp_address,
						  &addr);
			} else  {
				const char *real_addr = ast_strdupa(ast_sockaddr_stringify(&addr));
				const char *expected_addr = ast_strdupa(ast_sockaddr_stringify(&rtp->strict_rtp_address));

				ast_debug(1, "Received RTP packet from %s, dropping due to strict RTP protection. Expected it to be from %s\n",
						real_addr, expected_addr);

				return &ast_null_frame;
			}
		}
	}

	/* Get fields and verify this is an RTP packet */
	seqno = ntohl(rtpheader[0]);

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	if (!(version = (seqno & 0xC0000000) >> 30)) {
		struct sockaddr_in addr_tmp;
		struct ast_sockaddr addr_v4;
		if (ast_sockaddr_is_ipv4(&addr)) {
			ast_sockaddr_to_sin(&addr, &addr_tmp);
		} else if (ast_sockaddr_ipv4_mapped(&addr, &addr_v4)) {
			ast_debug(1, "Using IPv6 mapped address %s for STUN\n",
				  ast_sockaddr_stringify(&addr));
			ast_sockaddr_to_sin(&addr_v4, &addr_tmp);
		} else {
			ast_debug(1, "Cannot do STUN for non IPv4 address %s\n",
				  ast_sockaddr_stringify(&addr));
			return &ast_null_frame;
		}
		if ((ast_stun_handle_packet(rtp->s, &addr_tmp, rtp->rawdata + AST_FRIENDLY_OFFSET, res, NULL, NULL) == AST_STUN_ACCEPT) &&
		    ast_sockaddr_isnull(&remote_address)) {
			ast_sockaddr_from_sin(&addr, &addr_tmp);
			ast_rtp_instance_set_remote_address(instance, &addr);
		}
		return &ast_null_frame;
	}

#ifdef HAVE_OPENSSL
	/* A3: WebRTC ICE debug ("rtp set debug ice on"). On the first media packet after ICE completes AND on
	 * every media-source CHANGE, log the nominated ice_peer vs the ACTUAL media source. Live browsers send
	 * ICE/DTLS checks and SRTP media from DIFFERENT source ports (same IP): cmp!=0 but cmp_addr==0 — which is
	 * why the symmetric-RTP follow below is REQUIRED and an ice_peer host+port RX drop would kill audio. LOG ONLY. */
	if (rtpicedebug && version == 2 && rtp->ice_active && rtp->ice_complete
	    && (!rtp->rx_seen || ast_sockaddr_cmp(&rtp->last_media, &addr))) {	/* version==2: skip malformed RTP-like datagrams */
		char *p_peer = ast_strdupa(ast_sockaddr_stringify(&rtp->ice_peer));
		char *p_src = ast_strdupa(ast_sockaddr_stringify(&addr));
		ast_verbose("ICE-RXDBG inst=%p rtp=%p ice_peer=%s media_src=%s cmp=%d cmp_addr=%d dtls_conn=%d strict_state=%d first=%d pt=%d ssrc=%u\n",
			instance, rtp, p_peer, p_src,
			ast_sockaddr_cmp(&rtp->ice_peer, &addr), ast_sockaddr_cmp_addr(&rtp->ice_peer, &addr),
			(int)rtp->dtls.connection, (int)rtp->strict_rtp_state, !rtp->rx_seen,
			(int)((seqno >> 16) & 0x7f), (unsigned int)ntohl(rtpheader[2]));
		ast_sockaddr_copy(&rtp->last_media, &addr);
		rtp->rx_seen = 1;
	}
#endif

	/* ┌─ DO NOT ADD AN ICE "SELECTED-PAIR" RX DROP HERE ──────────────────────────────────────────────────┐
	 * │ A guard like `if (ice_active && ice_complete && ast_sockaddr_cmp(&ice_peer,&addr)) return null;` was │
	 * │ TRIED and DROPPED ALL AUDIO on live SIP.js, so it was REVERTED after review. The                     │
	 * │ browser sends ICE/DTLS checks and SRTP media from DIFFERENT source ports, SAME IP (cmp!=0, cmp_addr  │
	 * │ ==0 — see ICE-RXDBG above). The symmetric-RTP follow BELOW is load-bearing (moves media to its real  │
	 * │ source); SRTP auth/replay already rejects forgeries. Never host+port RX filter here. Log, don't drop.│
	 * └─────────────────────────────────────────────────────────────────────────────────────────────────────┘ */
	/* If symmetric RTP is enabled see if the remote side is not what we expected and change where we are sending audio */
	if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT)) {
		if (ast_sockaddr_cmp(&remote_address, &addr)) {
			ast_rtp_instance_set_remote_address(instance, &addr);
			ast_sockaddr_copy(&remote_address, &addr);
			if (rtp->rtcp) {
				ast_sockaddr_copy(&rtp->rtcp->them, &addr);
				ast_sockaddr_set_port(&rtp->rtcp->them, ast_sockaddr_port(&addr) + 1);
			}
			rtp->rxseqno = 0;
			ast_set_flag(rtp, FLAG_NAT_ACTIVE);
			if (option_debug || rtpdebug)
				ast_debug(0, "RTP NAT: Got audio from other end. Now sending to address %s\n",
					  ast_sockaddr_stringify(&remote_address));
		}
	}

	/* If we are directly bridged to another instance send the audio directly out */
	if (ast_rtp_instance_get_bridged(instance) && !bridge_p2p_rtp_write(instance, rtpheader, res, hdrlen)) {
		return &ast_null_frame;
	}

	/* If the version is not what we expected by this point then just drop the packet */
	if (version != 2) {
		return &ast_null_frame;
	}

	/* Pull out the various other fields we will need */
	payloadtype = (seqno & 0x7f0000) >> 16;
	padding = seqno & (1 << 29);
	mark = seqno & (1 << 23);
	ext = seqno & (1 << 28);
	cc = (seqno & 0xF000000) >> 24;
	seqno &= 0xffff;
	timestamp = ntohl(rtpheader[1]);
	ssrc = ntohl(rtpheader[2]);

	/* WebRTC BUNDLE: classify this packet's sub-stream by payload type so audio and the bundled video keep
	 * independent SSRC/seqno/cycle/count state (RFC 8843 PT-demux). rtp->bundle==0 => is_video==0 => every
	 * pointer below resolves to the existing audio field => byte-identical to the non-bundle path. */
	if (rtp->bundle) {
		struct ast_rtp_payload_type vpt = ast_rtp_codecs_payload_lookup(ast_rtp_instance_get_codecs(instance), payloadtype);
		is_video = vpt.gabpbx_format && (vpt.code & AST_FORMAT_VIDEO_MASK);
	}
	bundle_rxssrc = is_video ? &rtp->v_rxssrc : &rtp->rxssrc;
	bundle_rxcount = is_video ? &rtp->v_rxcount : &rtp->rxcount;
	bundle_lastrxseqno = is_video ? &rtp->v_lastrxseqno : &rtp->lastrxseqno;
	bundle_seedrxseqno = is_video ? &rtp->v_seedrxseqno : &rtp->seedrxseqno;
	bundle_cycles = is_video ? &rtp->v_cycles : &rtp->cycles;

	AST_LIST_HEAD_INIT_NOLOCK(&frames);
	/* Force a marker bit and change SSRC if the SSRC changes */
	if (*bundle_rxssrc && *bundle_rxssrc != ssrc) {
		struct ast_frame *f, srcupdate = {
			AST_FRAME_CONTROL,
			.subclass.integer = AST_CONTROL_SRCCHANGE,
		};

		if (!mark) {
			if (option_debug || rtpdebug) {
				ast_debug(1, "Forcing Marker bit, because SSRC has changed\n");
			}
			mark = 1;
		}

		f = ast_frisolate(&srcupdate);
		AST_LIST_INSERT_TAIL(&frames, f, frame_list);
	}

	*bundle_rxssrc = ssrc;

	/* Remove any padding bytes that may be present */
	if (padding) {
		res -= rtp->rawdata[AST_FRIENDLY_OFFSET + res - 1];
	}

	/* Skip over any CSRC fields */
	if (cc) {
		hdrlen += cc * 4;
	}

	/* Look for any RTP extensions, currently we do not support any */
	if (ext) {
		hdrlen += (ntohl(rtpheader[hdrlen/4]) & 0xffff) << 2;
		hdrlen += 4;
		if (option_debug) {
			int profile;
			profile = (ntohl(rtpheader[3]) & 0xffff0000) >> 16;
			if (profile == 0x505a)
				ast_debug(1, "Found Zfone extension in RTP stream - zrtp - not supported.\n");
			else
				ast_debug(1, "Found unknown RTP Extensions %x\n", profile);
		}
	}

	/* Make sure after we potentially mucked with the header length that it is once again valid */
	if (res < hdrlen) {
		ast_log(LOG_WARNING, "RTP Read too short (%d, expecting %d\n", res, hdrlen);
		return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
	}

	(*bundle_rxcount)++;
	if (*bundle_rxcount == 1) {
		*bundle_seedrxseqno = seqno;
	}

	/* Do not schedule RR if RTCP isn't run */
	if (rtp->rtcp && !ast_sockaddr_isnull(&rtp->rtcp->them) && rtp->rtcp->schedid < 1) {
		/* Schedule transmission of Receiver Report */
		ao2_ref(instance, +1);
		rtp->rtcp->schedid = ast_sched_add(rtp->sched, ast_rtcp_calc_interval(rtp), ast_rtcp_write, instance);
		if (rtp->rtcp->schedid < 0) {
			ao2_ref(instance, -1);
			ast_log(LOG_WARNING, "scheduling RTCP transmission failed.\n");
		}
	}
	if ((int)*bundle_lastrxseqno - (int)seqno  > 100) /* if so it would indicate that the sender cycled; allow for misordering */
		*bundle_cycles += RTP_SEQ_MOD;

	prev_seqno = *bundle_lastrxseqno;
	*bundle_lastrxseqno = seqno;

	if (!rtp->themssrc && !is_video) {
		rtp->themssrc = ntohl(rtpheader[2]); /* Record their SSRC to put in future RR (audio sub-stream only) */
	}

	if (rtp_debug_test_addr(&addr)) {
		ast_verbose("Got  RTP packet from    %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
			    ast_sockaddr_stringify(&addr),
			    payloadtype, seqno, timestamp,res - hdrlen);
	}

	payload = ast_rtp_codecs_payload_lookup(ast_rtp_instance_get_codecs(instance), payloadtype);

	/* If the payload is not actually an GABpbx one but a special one pass it off to the respective handler */
	if (!payload.gabpbx_format) {
		struct ast_frame *f = NULL;
		if (payload.code == AST_RTP_DTMF) {
			/* process_dtmf_rfc2833 may need to return multiple frames. We do this
			 * by passing the pointer to the frame list to it so that the method
			 * can append frames to the list as needed.
			 */
			process_dtmf_rfc2833(instance, rtp->rawdata + AST_FRIENDLY_OFFSET + hdrlen, res - hdrlen, seqno, timestamp, &addr, payloadtype, mark, &frames);
		} else if (payload.code == AST_RTP_CISCO_DTMF) {
			f = process_dtmf_cisco(instance, rtp->rawdata + AST_FRIENDLY_OFFSET + hdrlen, res - hdrlen, seqno, timestamp, &addr, payloadtype, mark);
		} else if (payload.code == AST_RTP_CN) {
			f = process_cn_rfc3389(instance, rtp->rawdata + AST_FRIENDLY_OFFSET + hdrlen, res - hdrlen, seqno, timestamp, &addr, payloadtype, mark);
		} /*else {
			ast_log(LOG_NOTICE, "Unknown RTP codec %d received from '%s'\n",
				payloadtype,
				ast_sockaddr_stringify(&remote_address));
		} */

		if (f) {
			AST_LIST_INSERT_TAIL(&frames, f, frame_list);
		}
		/* Even if no frame was returned by one of the above methods,
		 * we may have a frame to return in our frame list
		 */
		if (!AST_LIST_EMPTY(&frames)) {
			return AST_LIST_FIRST(&frames);
		}
		return &ast_null_frame;
	}

	rtp->f.subclass.codec = payload.code;
	/* lastrxformat feeds the audio DTMF (RFC 2833) / CN (RFC 3389) sample-rate calc; on a bundle leg keep it the
	 * AUDIO format so an interleaved video packet doesn't overwrite it. is_video is always 0 when !rtp->bundle => byte-identical. */
	if (!is_video) {
		rtp->lastrxformat = payload.code;
	}
	rtp->f.frametype = (rtp->f.subclass.codec & AST_FORMAT_AUDIO_MASK) ? AST_FRAME_VOICE : (rtp->f.subclass.codec & AST_FORMAT_VIDEO_MASK) ? AST_FRAME_VIDEO : AST_FRAME_TEXT;

	rtp->rxseqno = seqno;

	if (rtp->dtmf_timeout && rtp->dtmf_timeout < timestamp) {
		rtp->dtmf_timeout = 0;

		if (rtp->resp) {
			struct ast_frame *f;
			f = create_dtmf_frame(instance, AST_FRAME_DTMF_END, 0);
			f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.codec)), ast_tv(0, 0));
			rtp->resp = 0;
			rtp->dtmf_timeout = rtp->dtmf_duration = 0;
			AST_LIST_INSERT_TAIL(&frames, f, frame_list);
			return AST_LIST_FIRST(&frames);
		}
	}

	rtp->lastrxts = timestamp;

	rtp->f.src = "RTP";
	rtp->f.mallocd = 0;
	rtp->f.datalen = res - hdrlen;
	rtp->f.data.ptr = rtp->rawdata + hdrlen + AST_FRIENDLY_OFFSET;
	rtp->f.offset = hdrlen + AST_FRIENDLY_OFFSET;
	rtp->f.seqno = seqno;

	if (rtp->f.subclass.codec == AST_FORMAT_T140 && (int)seqno - (prev_seqno + 1) > 0 && (int)seqno - (prev_seqno + 1) < 10) {
		/* Mark the gap of lost T.140 packets. RFC 4103 §5.3 (rfc4103.txt:464-477) calls for one
		 * missing-text marker per missing T140block; prepend them into the frame's leading headroom
		 * rather than tail-growing with memmove, which on a max-size packet would write 3 bytes past
		 * rtp->rawdata into the next struct field. */
		rtp_t140_prepend_markers(&rtp->f, (int)seqno - (prev_seqno + 1));
	}

	if (rtp->f.subclass.codec == AST_FORMAT_T140RED) {
		/* RFC 2198 redundancy parse for RFC 4103 T.140 text. The previous code located the primary
		 * header with memchr() and read each block length from a single byte (data[x*4+3]); both are
		 * non-conformant. RFC 2198 (rfc2198.txt:218-248) defines each redundant header as 4 bytes
		 * (F bit, 7-bit PT, 14-bit timestamp offset, 10-bit block length) walked by the F bit and
		 * terminated by a 1-byte primary header (F=0, rfc2198.txt:290-306). We walk by the F bit, read
		 * the full 10-bit length, and bound every offset by datalen — the old paths over-read a crafted
		 * RED packet and the diff>num_gen branch's `len -= 3` underflowed datalen / wrote before the
		 * buffer when there were no redundant generations. */
		unsigned char *data = rtp->f.data.ptr;
		int datalen = rtp->f.datalen;
		int diff = (int) seqno - (prev_seqno + 1);	/* 0 = in order, >0 = gap, <0 = out of order */
		int gen_len[AST_RED_MAX_GENERATION];
		int num_gen = 0;
		int red_total = 0;	/* total bytes of the redundant data blocks (before the primary) */
		int hdr_len = 0, skip, x;

		rtp->f.subclass.codec = AST_FORMAT_T140;

		/* Walk the redundant block headers (F bit set), reading the 10-bit block length. */
		while (hdr_len < datalen && (data[hdr_len] & 0x80)) {
			if (num_gen >= AST_RED_MAX_GENERATION || hdr_len + 4 > datalen) {
				return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
			}
			gen_len[num_gen] = ((data[hdr_len + 2] & 0x03) << 8) | data[hdr_len + 3];
			red_total += gen_len[num_gen];
			num_gen++;
			hdr_len += 4;
		}
		if (hdr_len >= datalen) {	/* the 1-byte primary (F=0) header must follow */
			return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
		}
		hdr_len += 1;

		/* All headers + every redundant data block must fit, leaving the primary block. */
		if (hdr_len + red_total > datalen) {
			return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
		}

		if (diff <= 0) {
			/* In order (diff==0) or out-of-order/duplicate (diff<0): deliver only the primary block.
			 * RFC 4103 §4.2 (rfc4103.txt:351-382) infers loss from sequence gaps, so an out-of-order
			 * packet carries no recoverable new text; never index past the generations (the old
			 * num_gen-diff loop over-read for diff<0). */
			skip = hdr_len + red_total;
			if (skip >= datalen) {	/* empty primary, nothing to deliver */
				return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
			}
		} else if (diff <= num_gen) {
			/* 1<=diff<=generations: the redundant generation covering the lost text is present;
			 * deliver from it through the primary (generations are age-ordered, most recent last,
			 * rfc4103.txt:361-374) by skipping the headers and the older redundant blocks. */
			skip = hdr_len;
			for (x = 0; x < num_gen - diff; x++) {
				skip += gen_len[x];
			}
		} else {
			/* diff>generations: the gap exceeds what the redundancy can recover. Deliver every
			 * redundant generation + the primary (skip only the headers) and prepend a missing-text
			 * marker per unrecoverable older packet (RFC 4103 §5.3). */
			skip = hdr_len;
		}

		rtp->f.data.ptr = (unsigned char *) rtp->f.data.ptr + skip;
		rtp->f.datalen = datalen - skip;
		rtp->f.offset += skip;	/* keep the headroom invariant so a marker prepend below sizes from old+skip */

		if (diff > num_gen && diff < 10) {
			rtp_t140_prepend_markers(&rtp->f, diff - num_gen);
		}
	}

	if (rtp->f.subclass.codec & AST_FORMAT_AUDIO_MASK) {
		rtp->f.samples = ast_codec_get_samples(&rtp->f);
		if ((rtp->f.subclass.codec == AST_FORMAT_SLINEAR) || (rtp->f.subclass.codec == AST_FORMAT_SLINEAR16)) {
			ast_frame_byteswap_be(&rtp->f);
		}
		calc_rxstamp(&rtp->f.delivery, rtp, timestamp, mark);
		/* Add timing data to let ast_generic_bridge() put the frame into a jitterbuf */
		ast_set_flag(&rtp->f, AST_FRFLAG_HAS_TIMING_INFO);
		rtp->f.ts = timestamp / (rtp_get_rate(rtp->f.subclass.codec) / 1000);
		rtp->f.len = rtp->f.samples / ((ast_format_rate(rtp->f.subclass.codec) / 1000));
	} else if (rtp->f.subclass.codec & AST_FORMAT_VIDEO_MASK) {
		/* Video -- samples is # of samples vs. 90000 */
		if (!rtp->lastividtimestamp)
			rtp->lastividtimestamp = timestamp;
		rtp->f.samples = timestamp - rtp->lastividtimestamp;
		rtp->lastividtimestamp = timestamp;
		rtp->f.delivery.tv_sec = 0;
		rtp->f.delivery.tv_usec = 0;
		/* Pass the RTP marker bit as bit 0 in the subclass field.
		 * This is ok because subclass is actually a bitmask, and
		 * the low bits represent audio formats, that are not
		 * involved here since we deal with video.
		 */
		if (mark)
			rtp->f.subclass.codec |= 0x1;
	} else {
		/* TEXT -- samples is # of samples vs. 1000 */
		if (!rtp->lastitexttimestamp)
			rtp->lastitexttimestamp = timestamp;
		rtp->f.samples = timestamp - rtp->lastitexttimestamp;
		rtp->lastitexttimestamp = timestamp;
		rtp->f.delivery.tv_sec = 0;
		rtp->f.delivery.tv_usec = 0;
	}

	AST_LIST_INSERT_TAIL(&frames, &rtp->f, frame_list);
	return AST_LIST_FIRST(&frames);
}

static void ast_rtp_prop_set(struct ast_rtp_instance *instance, enum ast_rtp_property property, int value)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (property == AST_RTP_PROPERTY_RTCP) {
		if (value) {
			if (rtp->rtcp) {
				ast_debug(1, "Ignoring duplicate RTCP property on RTP instance '%p'\n", instance);
				return;
			}
			/* Setup RTCP to be activated on the next RTP write */
			if (!(rtp->rtcp = ast_calloc(1, sizeof(*rtp->rtcp)))) {
				return;
			}

			/* Grab the IP address and port we are going to use */
			ast_rtp_instance_get_local_address(instance, &rtp->rtcp->us);
			ast_sockaddr_set_port(&rtp->rtcp->us,
					      ast_sockaddr_port(&rtp->rtcp->us) + 1);

			if ((rtp->rtcp->s =
			     create_new_socket("RTCP",
					       ast_sockaddr_is_ipv4(&rtp->rtcp->us) ?
					       AF_INET :
					       ast_sockaddr_is_ipv6(&rtp->rtcp->us) ?
					       AF_INET6 : -1)) < 0) {
				ast_debug(1, "Failed to create a new socket for RTCP on instance '%p'\n", instance);
				ast_free(rtp->rtcp);
				rtp->rtcp = NULL;
				return;
			}

			/* Try to actually bind to the IP address and port we are going to use for RTCP, if this fails we have to bail out */
			if (ast_bind(rtp->rtcp->s, &rtp->rtcp->us)) {
				ast_debug(1, "Failed to setup RTCP on RTP instance '%p'\n", instance);
				close(rtp->rtcp->s);
				ast_free(rtp->rtcp);
				rtp->rtcp = NULL;
				return;
			}

			ast_debug(1, "Setup RTCP on RTP instance '%p'\n", instance);
			rtp->rtcp->schedid = -1;

			return;
		} else {
			if (rtp->rtcp) {
				if (rtp->rtcp->schedid > 0) {
					if (!ast_sched_del(rtp->sched, rtp->rtcp->schedid)) {
						/* Successfully cancelled scheduler entry. */
						ao2_ref(instance, -1);
					} else {
						/* Unable to cancel scheduler entry */
						ast_debug(1, "Failed to tear down RTCP on RTP instance '%p'\n", instance);
						return;
					}
					rtp->rtcp->schedid = -1;
				}
				close(rtp->rtcp->s);
				ast_free(rtp->rtcp);
				rtp->rtcp = NULL;
			}
			return;
		}
	}

	if (property == AST_RTP_PROPERTY_BUNDLE) {
		/* WebRTC BUNDLE (RFC 8843): carry audio + a PT-demuxed video sub-stream on this one transport.
		 * RTX/FEC/NACK and a per-SSRC video RTCP RR are out of scope for v1 (follow-up). */
		rtp->bundle = value ? 1 : 0;
		return;
	}

	return;
}

static int ast_rtp_fd(struct ast_rtp_instance *instance, int rtcp)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtcp ? (rtp->rtcp ? rtp->rtcp->s : -1) : rtp->s;
}

static void ast_rtp_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (rtp->rtcp) {
		ast_debug(1, "Setting RTCP address on RTP instance '%p'\n", instance);
		ast_sockaddr_copy(&rtp->rtcp->them, addr);
		if (!ast_sockaddr_isnull(addr)) {
			ast_sockaddr_set_port(&rtp->rtcp->them,
					      ast_sockaddr_port(addr) + 1);
		}
	}

	rtp->rxseqno = 0;

	if (strictrtp) {
		rtp->strict_rtp_state = STRICT_RTP_LEARN;
		rtp_learning_seq_init(rtp, rtp->seqno);
	}

	return;
}

static void ast_rtp_alt_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* No need to futz with rtp->rtcp here because ast_rtcp_read is already able to adjust if receiving
	 * RTCP from an "unexpected" source
	 */
	ast_sockaddr_copy(&rtp->alt_rtp_address, addr);

	return;
}

/*! \brief Write t140 redundacy frame
 * \param data primary data to be buffered
 */
static int red_write(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance*) data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	ast_rtp_write(instance, &rtp->red->t140);

	return 1;
}

static int rtp_red_init(struct ast_rtp_instance *instance, int buffer_time, int *payloads, int generations)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int x;

	/* `generations` indexes pt/ts/len (and the primary at index `generations`); the public engine API
	 * ast_rtp_red_init can pass an arbitrary value, so bound it to the array capacity (0..MAX inclusive). */
	if (generations < 1 || generations > AST_RED_MAX_GENERATION) {
		ast_log(LOG_WARNING, "RED init refused: generations=%d out of range [1..%d]\n",
			generations, AST_RED_MAX_GENERATION);
		return -1;
	}

	if (!(rtp->red = ast_calloc(1, sizeof(*rtp->red)))) {
		return -1;
	}

	rtp->red->t140.frametype = AST_FRAME_TEXT;
	rtp->red->t140.subclass.codec = AST_FORMAT_T140RED;
	rtp->red->t140.data.ptr = &rtp->red->buf_data;

	rtp->red->t140.ts = 0;
	rtp->red->t140red = rtp->red->t140;
	rtp->red->t140red.data.ptr = &rtp->red->t140red_data;
	rtp->red->t140red.datalen = 0;
	rtp->red->ti = buffer_time;
	rtp->red->num_gen = generations;
	rtp->red->hdrlen = generations * 4 + 1;
	rtp->red->prev_ts = 0;

	for (x = 0; x < generations; x++) {
		rtp->red->pt[x] = payloads[x];
		rtp->red->pt[x] |= 1 << 7; /* mark redundant generations pt */
		rtp->red->t140red_data[x*4] = rtp->red->pt[x];
	}
	rtp->red->t140red_data[x*4] = rtp->red->pt[x] = payloads[x]; /* primary pt */
	rtp->red->schedid = ast_sched_add(rtp->sched, generations, red_write, instance);

	rtp->red->t140.datalen = 0;

	return 0;
}

static int rtp_red_buffer(struct ast_rtp_instance *instance, struct ast_frame *frame)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (frame->datalen > 0) {
		struct rtp_red *red = rtp->red;
		/* Bound the accumulation: t140.datalen only resets after a send (red_t140_to_red), so a burst of
		 * T.140 faster than the buffer timer would otherwise smash the heap. The accumulated primary must fit
		 * in BOTH buf_data AND the RED OUTPUT (t140red_data), which also carries the header + up to num_gen
		 * redundant blocks (each <=1023 by the promote-guard in red_t140_to_red). Cap against the tighter of
		 * the two so neither memcpy (here, or the primary copy in red_t140_to_red) can overflow.
		 * (datalen<=0 is also skipped now - a negative datalen would be a huge size_t to memcpy.) */
		int max_primary = (int) sizeof(red->t140red_data) - red->hdrlen - red->num_gen * 1023;
		if (max_primary > (int) sizeof(red->buf_data)) {
			max_primary = (int) sizeof(red->buf_data);
		}
		if (max_primary < 0) {
			max_primary = 0;
		}
		if (red->t140.datalen + frame->datalen > max_primary) {
			ast_log(LOG_WARNING, "RED T.140: buffer full (have %d + %d > cap %d); dropping frame to avoid overflow\n",
				red->t140.datalen, frame->datalen, max_primary);
			return 0;
		}
		memcpy(&red->buf_data[red->t140.datalen], frame->data.ptr, frame->datalen);
		red->t140.datalen += frame->datalen;
		red->t140.ts = frame->ts;
	}

	return 0;
}

static int ast_rtp_local_bridge(struct ast_rtp_instance *instance0, struct ast_rtp_instance *instance1)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance0);

	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);

	return 0;
}

static int ast_rtp_get_stat(struct ast_rtp_instance *instance, struct ast_rtp_instance_stats *stats, enum ast_rtp_instance_stat stat)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* SSRC stats need NO RTCP: serve them BEFORE the rtcp guard so SDP generation (a=ssrc / a=msid), which can
	 * run before RTCP is set up — e.g. an outbound WebRTC OFFER — reads the real local/video SSRC instead of 0.
	 * Previously get_stat returned -1 here when rtcp was NULL, so our OFFER emitted NO a=ssrc/a=msid and the
	 * browser never instantiated an inbound video receiver (no inbound-rtp video -> black). The ANSWER worked
	 * only because RTCP was already set up by then. */
	if (stat == AST_RTP_INSTANCE_STAT_LOCAL_SSRC) {
		stats->local_ssrc = rtp->ssrc;
		return 0;
	}
	if (stat == AST_RTP_INSTANCE_STAT_LOCAL_VIDEO_SSRC) {
		stats->local_video_ssrc = rtp->v_ssrc;
		return 0;
	}
	if (stat == AST_RTP_INSTANCE_STAT_REMOTE_SSRC) {
		stats->remote_ssrc = rtp->themssrc;
		return 0;
	}

	if (!rtp->rtcp) {
		return -1;
	}

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXCOUNT, -1, stats->txcount, rtp->txcount);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXCOUNT, -1, stats->rxcount, rtp->rxcount);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->txploss, rtp->rtcp->reported_lost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->rxploss, rtp->rtcp->expected_prior - rtp->rtcp->received_prior);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MAXRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_maxrxploss, rtp->rtcp->reported_maxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MINRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_minrxploss, rtp->rtcp->reported_minlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_NORMDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_normdevrxploss, rtp->rtcp->reported_normdev_lost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_STDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_stdevrxploss, rtp->rtcp->reported_stdev_lost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MAXRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_maxrxploss, rtp->rtcp->maxrxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MINRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_minrxploss, rtp->rtcp->minrxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_NORMDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_normdevrxploss, rtp->rtcp->normdev_rxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_STDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_stdevrxploss, rtp->rtcp->stdev_rxlost);
	AST_RTP_STAT_TERMINATOR(AST_RTP_INSTANCE_STAT_COMBINED_LOSS);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->txjitter, rtp->rxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->rxjitter, rtp->rtcp->reported_jitter / (unsigned int) 65536.0);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MAXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_maxjitter, rtp->rtcp->reported_maxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MINJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_minjitter, rtp->rtcp->reported_minjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_NORMDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_normdevjitter, rtp->rtcp->reported_normdev_jitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_STDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_stdevjitter, rtp->rtcp->reported_stdev_jitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MAXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_maxjitter, rtp->rtcp->maxrxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MINJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_minjitter, rtp->rtcp->minrxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_NORMDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_normdevjitter, rtp->rtcp->normdev_rxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_STDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_stdevjitter, rtp->rtcp->stdev_rxjitter);
	AST_RTP_STAT_TERMINATOR(AST_RTP_INSTANCE_STAT_COMBINED_JITTER);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->rtt, rtp->rtcp->rtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_MAX_RTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->maxrtt, rtp->rtcp->maxrtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_MIN_RTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->minrtt, rtp->rtcp->minrtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_NORMDEVRTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->normdevrtt, rtp->rtcp->normdevrtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_STDEVRTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->stdevrtt, rtp->rtcp->stdevrtt);
	AST_RTP_STAT_TERMINATOR(AST_RTP_INSTANCE_STAT_COMBINED_RTT);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_SSRC, -1, stats->local_ssrc, rtp->ssrc);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_SSRC, -1, stats->remote_ssrc, rtp->themssrc);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_VIDEO_SSRC, -1, stats->local_video_ssrc, rtp->v_ssrc);

	return 0;
}

static int ast_rtp_dtmf_compatible(struct ast_channel *chan0, struct ast_rtp_instance *instance0, struct ast_channel *chan1, struct ast_rtp_instance *instance1)
{
	/* If both sides are not using the same method of DTMF transmission
	 * (ie: one is RFC2833, other is INFO... then we can not do direct media.
	 * --------------------------------------------------
	 * | DTMF Mode |  HAS_DTMF  |  Accepts Begin Frames |
	 * |-----------|------------|-----------------------|
	 * | Inband    | False      | True                  |
	 * | RFC2833   | True       | True                  |
	 * | SIP INFO  | False      | False                 |
	 * --------------------------------------------------
	 */
	return (((ast_rtp_instance_get_prop(instance0, AST_RTP_PROPERTY_DTMF) != ast_rtp_instance_get_prop(instance1, AST_RTP_PROPERTY_DTMF)) ||
		 (!chan0->tech->send_digit_begin != !chan1->tech->send_digit_begin)) ? 0 : 1);
}

static void ast_rtp_stun_request(struct ast_rtp_instance *instance, struct ast_sockaddr *suggestion, const char *username)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct sockaddr_in suggestion_tmp;

	ast_sockaddr_to_sin(suggestion, &suggestion_tmp);
	ast_stun_request(rtp->s, &suggestion_tmp, username, NULL);
	ast_sockaddr_from_sin(suggestion, &suggestion_tmp);
}

static void ast_rtp_stop(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr addr = { {0,} };

	if (rtp->rtcp && rtp->rtcp->schedid > 0) {
		if (!ast_sched_del(rtp->sched, rtp->rtcp->schedid)) {
			/* successfully cancelled scheduler entry. */
			ao2_ref(instance, -1);
		}
		rtp->rtcp->schedid = -1;
	}

	if (rtp->red) {
		AST_SCHED_DEL(rtp->sched, rtp->red->schedid);
		free(rtp->red);
		rtp->red = NULL;
	}

	// germanico verify if lost any rtp packet

	ast_rtp_instance_set_remote_address(instance, &addr);
	if (rtp->rtcp) {
		ast_sockaddr_setnull(&rtp->rtcp->them);
	}

	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);
}

static int ast_rtp_qos_set(struct ast_rtp_instance *instance, int tos, int cos, const char *desc)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return ast_set_qos(rtp->s, tos, cos, desc);
}

/*! \brief generate comfort noice (CNG) */
static int ast_rtp_sendcng(struct ast_rtp_instance *instance, int level)
{
	unsigned int *rtpheader;
	int hdrlen = 12;
	int res;
	struct ast_rtp_payload_type payload;
	char data[256];
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}

	payload = ast_rtp_codecs_payload_lookup(ast_rtp_instance_get_codecs(instance), AST_RTP_CN);

	level = 127 - (level & 0x7f);
	
	rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, 500000));

	/* Get a pointer to the header */
	rtpheader = (unsigned int *)data;
	rtpheader[0] = htonl((2 << 30) | (1 << 23) | (payload.code << 16) | (rtp->seqno++));
	rtpheader[1] = htonl(rtp->lastts);
	rtpheader[2] = htonl(rtp->ssrc); 
	data[12] = level;

	res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 1, 0, &remote_address);

	if (res < 0) {
		ast_log(LOG_ERROR, "RTP Comfort Noise Transmission error to %s: %s\n", ast_sockaddr_stringify(&remote_address), strerror(errno));
	} else if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Sent Comfort Noise RTP packet to %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
				ast_sockaddr_stringify(&remote_address),
				AST_RTP_CN, rtp->seqno, rtp->lastdigitts, res - hdrlen);
	}

	return res;
}

static char *rtp_do_debug_ip(struct ast_cli_args *a)
{
	char *arg = ast_strdupa(a->argv[4]);
	char *debughost = NULL;
	char *debugport = NULL;

	if (!ast_sockaddr_parse(&rtpdebugaddr, arg, 0) || !ast_sockaddr_split_hostport(arg, &debughost, &debugport, 0)) {
		ast_cli(a->fd, "Lookup failed for '%s'\n", arg);
		return CLI_FAILURE;
	}
	rtpdebugport = (!ast_strlen_zero(debugport) && debugport[0] != '0');
	ast_cli(a->fd, "RTP Debugging Enabled for address: %s\n",
		ast_sockaddr_stringify(&rtpdebugaddr));
	rtpdebug = 1;
	return CLI_SUCCESS;
}

static char *rtcp_do_debug_ip(struct ast_cli_args *a)
{
	char *arg = ast_strdupa(a->argv[4]);
	char *debughost = NULL;
	char *debugport = NULL;

	if (!ast_sockaddr_parse(&rtcpdebugaddr, arg, 0) || !ast_sockaddr_split_hostport(arg, &debughost, &debugport, 0)) {
		ast_cli(a->fd, "Lookup failed for '%s'\n", arg);
		return CLI_FAILURE;
	}
	rtcpdebugport = (!ast_strlen_zero(debugport) && debugport[0] != '0');
	ast_cli(a->fd, "RTCP Debugging Enabled for address: %s\n",
		ast_sockaddr_stringify(&rtcpdebugaddr));
	rtcpdebug = 1;
	return CLI_SUCCESS;
}

static char *handle_cli_rtp_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtp set debug {on|off|ip}";
		e->usage =
			"Usage: rtp set debug {on|off|ip host[:port]}\n"
			"       Enable/Disable dumping of all RTP packets. If 'ip' is\n"
			"       specified, limit the dumped packets to those to and from\n"
			"       the specified 'host' with optional port.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc == e->args) { /* set on or off */
		if (!strncasecmp(a->argv[e->args-1], "on", 2)) {
			rtpdebug = 1;
			memset(&rtpdebugaddr, 0, sizeof(rtpdebugaddr));
			ast_cli(a->fd, "RTP Debugging Enabled\n");
			return CLI_SUCCESS;
		} else if (!strncasecmp(a->argv[e->args-1], "off", 3)) {
			rtpdebug = 0;
			ast_cli(a->fd, "RTP Debugging Disabled\n");
			return CLI_SUCCESS;
		}
	} else if (a->argc == e->args +1) { /* ip */
		return rtp_do_debug_ip(a);
	}

	return CLI_SHOWUSAGE;   /* default, failure */
}

static char *handle_cli_rtp_set_debug_ice(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtp set debug ice {on|off}";
		e->usage =
			"Usage: rtp set debug ice {on|off}\n"
			"       Enable/Disable WebRTC ICE/DTLS debugging (pure logging, no media change).\n"
			"       Logs each ICE latch/nomination (this driver is LATCH-ALWAYS), DTLS records\n"
			"       dropped as source != the latched peer, and (on the first media packet\n"
			"       after ICE completes + on every media-source change) the nominated peer\n"
			"       vs the actual media source - which legitimately differ by port for some\n"
			"       browsers. Never logs secrets. Default OFF.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc == e->args) {
		if (!strncasecmp(a->argv[e->args-1], "on", 2)) {
			rtpicedebug = 1;
			ast_cli(a->fd, "WebRTC ICE Debugging Enabled\n");
			return CLI_SUCCESS;
		} else if (!strncasecmp(a->argv[e->args-1], "off", 3)) {
			rtpicedebug = 0;
			ast_cli(a->fd, "WebRTC ICE Debugging Disabled\n");
			return CLI_SUCCESS;
		}
	}

	return CLI_SHOWUSAGE;
}

static char *handle_cli_rtcp_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtcp set debug {on|off|ip}";
		e->usage =
			"Usage: rtcp set debug {on|off|ip host[:port]}\n"
			"       Enable/Disable dumping of all RTCP packets. If 'ip' is\n"
			"       specified, limit the dumped packets to those to and from\n"
			"       the specified 'host' with optional port.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc == e->args) { /* set on or off */
		if (!strncasecmp(a->argv[e->args-1], "on", 2)) {
			rtcpdebug = 1;
			memset(&rtcpdebugaddr, 0, sizeof(rtcpdebugaddr));
			ast_cli(a->fd, "RTCP Debugging Enabled\n");
			return CLI_SUCCESS;
		} else if (!strncasecmp(a->argv[e->args-1], "off", 3)) {
			rtcpdebug = 0;
			ast_cli(a->fd, "RTCP Debugging Disabled\n");
			return CLI_SUCCESS;
		}
	} else if (a->argc == e->args +1) { /* ip */
		return rtcp_do_debug_ip(a);
	}

	return CLI_SHOWUSAGE;   /* default, failure */
}

static char *handle_cli_rtcp_set_stats(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtcp set stats {on|off}";
		e->usage =
			"Usage: rtcp set stats {on|off}\n"
			"       Enable/Disable dumping of RTCP stats.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != e->args)
		return CLI_SHOWUSAGE;

	if (!strncasecmp(a->argv[e->args-1], "on", 2))
		rtcpstats = 1;
	else if (!strncasecmp(a->argv[e->args-1], "off", 3))
		rtcpstats = 0;
	else
		return CLI_SHOWUSAGE;

	ast_cli(a->fd, "RTCP Stats %s\n", rtcpstats ? "Enabled" : "Disabled");
	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_rtp[] = {
	AST_CLI_DEFINE(handle_cli_rtp_set_debug,  "Enable/Disable RTP debugging"),
	AST_CLI_DEFINE(handle_cli_rtp_set_debug_ice,  "Enable/Disable WebRTC ICE/DTLS debugging"),
	AST_CLI_DEFINE(handle_cli_rtcp_set_debug, "Enable/Disable RTCP debugging"),
	AST_CLI_DEFINE(handle_cli_rtcp_set_stats, "Enable/Disable RTCP stats"),
};

static int rtp_reload(int reload)
{
	struct ast_config *cfg;
	const char *s;
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };

	cfg = ast_config_load2("rtp.conf", "rtp", config_flags);
	if (cfg == CONFIG_STATUS_FILEMISSING || cfg == CONFIG_STATUS_FILEUNCHANGED || cfg == CONFIG_STATUS_FILEINVALID) {
		return 0;
	}

	rtpstart = DEFAULT_RTP_START;
	rtpend = DEFAULT_RTP_END;
	dtmftimeout = DEFAULT_DTMF_TIMEOUT;
	strictrtp = STRICT_RTP_OPEN;
	learning_min_sequential = DEFAULT_LEARNING_MIN_SEQUENTIAL;
	if (cfg) {
		if ((s = ast_variable_retrieve(cfg, "general", "rtpstart"))) {
			rtpstart = atoi(s);
			if (rtpstart < MINIMUM_RTP_PORT)
				rtpstart = MINIMUM_RTP_PORT;
			if (rtpstart > MAXIMUM_RTP_PORT)
				rtpstart = MAXIMUM_RTP_PORT;
		}
		if ((s = ast_variable_retrieve(cfg, "general", "rtpend"))) {
			rtpend = atoi(s);
			if (rtpend < MINIMUM_RTP_PORT)
				rtpend = MINIMUM_RTP_PORT;
			if (rtpend > MAXIMUM_RTP_PORT)
				rtpend = MAXIMUM_RTP_PORT;
		}
		if ((s = ast_variable_retrieve(cfg, "general", "rtcpinterval"))) {
			rtcpinterval = atoi(s);
			if (rtcpinterval == 0)
				rtcpinterval = 0; /* Just so we're clear... it's zero */
			if (rtcpinterval < RTCP_MIN_INTERVALMS)
				rtcpinterval = RTCP_MIN_INTERVALMS; /* This catches negative numbers too */
			if (rtcpinterval > RTCP_MAX_INTERVALMS)
				rtcpinterval = RTCP_MAX_INTERVALMS;
		}
		if ((s = ast_variable_retrieve(cfg, "general", "rtpchecksums"))) {
#ifdef SO_NO_CHECK
			nochecksums = ast_false(s) ? 1 : 0;
#else
			if (ast_false(s))
				ast_log(LOG_WARNING, "Disabling RTP checksums is not supported on this operating system!\n");
#endif
		}
		if ((s = ast_variable_retrieve(cfg, "general", "dtmftimeout"))) {
			dtmftimeout = atoi(s);
			if ((dtmftimeout < 0) || (dtmftimeout > 64000)) {
				ast_log(LOG_WARNING, "DTMF timeout of '%d' outside range, using default of '%d' instead\n",
					dtmftimeout, DEFAULT_DTMF_TIMEOUT);
				dtmftimeout = DEFAULT_DTMF_TIMEOUT;
			};
		}
		if ((s = ast_variable_retrieve(cfg, "general", "strictrtp"))) {
			strictrtp = ast_true(s);
		}
		if ((s = ast_variable_retrieve(cfg, "general", "probation"))) {
			if ((sscanf(s, "%d", &learning_min_sequential) <= 0) || learning_min_sequential <= 0) {
				ast_log(LOG_WARNING, "Value for 'probation' could not be read, using default of '%d' instead\n",
					DEFAULT_LEARNING_MIN_SEQUENTIAL);
			}
		}
		ast_config_destroy(cfg);
	}
	if (rtpstart >= rtpend) {
		ast_log(LOG_WARNING, "Unreasonable values for RTP start/end port in rtp.conf\n");
		rtpstart = DEFAULT_RTP_START;
		rtpend = DEFAULT_RTP_END;
	}
	ast_verb(2, "RTP Allocating from port range %d -> %d\n", rtpstart, rtpend);
	return 0;
}

static int reload_module(void)
{
	rtp_reload(1);
	return 0;
}

static int load_module(void)
{
	if (ast_rtp_engine_register(&gabpbx_rtp_engine)) {
		return AST_MODULE_LOAD_DECLINE;
	}

	if (ast_cli_register_multiple(cli_rtp, ARRAY_LEN(cli_rtp))) {
		ast_rtp_engine_unregister(&gabpbx_rtp_engine);
		return AST_MODULE_LOAD_DECLINE;
	}

#ifdef HAVE_OPENSSL
	/* WebRTC A2: the DTLS write-BIO method that drains handshake records to the RTP socket. Allocated
	 * AFTER the registrations so a DECLINEd load (whose unload_module never runs) cannot leak it (MED3). */
	dtls_bio_methods = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "rtp dtls");
	if (dtls_bio_methods) {
		BIO_meth_set_write(dtls_bio_methods, dtls_bio_write);
		BIO_meth_set_ctrl(dtls_bio_methods, dtls_bio_ctrl);
		BIO_meth_set_create(dtls_bio_methods, dtls_bio_new);
		BIO_meth_set_destroy(dtls_bio_methods, dtls_bio_free);
	} else {
		ast_log(LOG_WARNING, "Failed to create the DTLS write-BIO method; DTLS-SRTP (WebRTC media) will be unavailable\n");
	}
	/* WebRTC A3: build the ICE STUN FINGERPRINT CRC-32 table once (no lazy-init data race). */
	ice_crc32_init();

	/* Dedicated WAKING scheduler for DTLS handshake retransmit timers (see dtls_sched_thread). Created
	 * here, after the engine/CLI registrations, so a DECLINEd load (whose unload_module never runs) is
	 * clean. Leave it NULL on failure → gabpbx_dtls_set_configuration fails closed (no WebRTC DTLS
	 * without a working retransmit timer). */
	if (!(dtls_sched_thread = ast_sched_thread_create())) {
		ast_log(LOG_WARNING, "Failed to create the DTLS retransmit scheduler; DTLS-SRTP (WebRTC media) will be unavailable\n");
	}
#endif

	rtp_reload(0);

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_rtp_engine_unregister(&gabpbx_rtp_engine);
	ast_cli_unregister_multiple(cli_rtp, ARRAY_LEN(cli_rtp));

#ifdef HAVE_OPENSSL
	if (dtls_bio_methods) {
		BIO_meth_free(dtls_bio_methods);
		dtls_bio_methods = NULL;
	}
	if (dtls_sched_thread) {
		dtls_sched_thread = ast_sched_thread_destroy(dtls_sched_thread);	/* joins the thread, then frees the context */
	}
#endif

	return 0;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "GABpbx RTP Stack",
		.load = load_module,
		.unload = unload_module,
		.reload = reload_module,
		.load_pri = AST_MODPRI_CHANNEL_DEPEND,
		);
