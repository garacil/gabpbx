/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * GABPBX as a project is based on Asterisk 1.8 and was later updated
 * to the final stable Asterisk 1.8 release.
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 *
 * Existing copyright, authorship, Asterisk/Digium notices,
 * third-party notices, and GPL licensing terms are preserved when present.
 *
 * Copyright (C) 2006 - 2007, Mikael Magnusson
 *
 * Mikael Magnusson <mikma@users.sourceforge.net>
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

/*! \file sdp_crypto.h
 *
 * \brief SDP Security descriptions
 *
 * Specified in RFC 4568
 */

#ifndef _SOFIA_SDP_CRYPTO_H
#define _SOFIA_SDP_CRYPTO_H

#include <gabpbx/rtp_engine.h>

struct sdp_crypto;

/*! \brief Initialize an return an sdp_crypto struct
 *
 * \details
 * This function allocates a new sdp_crypto struct and initializes its values
 *
 * \retval NULL on failure
 * \retval a pointer to a  new sdp_crypto structure
 */
struct sdp_crypto *sdp_crypto_setup(void);

/*! \brief Destroy a previously allocated sdp_crypto struct */
void sdp_crypto_destroy(struct sdp_crypto *crypto);

/*! \brief Parse the a=crypto line from SDP and set appropriate values on the
 * sdp_crypto struct.
 *
 * \param p A valid sdp_crypto struct
 * \param attr the a:crypto line from SDP
 * \param rtp The rtp instance associated with the SDP being parsed
 *
 * \retval 0 success
 * \retval nonzero failure
 */
int sdp_crypto_process(struct sdp_crypto *p, const char *attr, struct ast_rtp_instance *rtp);


/*! \brief Generate an SRTP a=crypto offer
 *
 * \details
 * The offer is stored on the sdp_crypto struct in a_crypto
 *
 * \param A valid sdp_crypto struct
 *
 * \retval 0 success
 * \retval nonzero failure
 */
int sdp_crypto_offer(struct sdp_crypto *p);

/*! \brief Generate a multi-line SRTP a=crypto offer with operator-configured cipher preference.
 *
 * \details
 * cipher_list is a comma-separated list of suite names (e.g.
 * "AEAD_AES_256_GCM,AES_CM_256_HMAC_SHA1_80,AES_CM_128_HMAC_SHA1_80"). Each
 * recognized suite is emitted on its own a=crypto:N line per RFC 4568 §6.1
 * tag-numbering, in operator-supplied order; peer answers with the chosen tag.
 * Unknown suite names are skipped with LOG_WARNING. Empty/NULL cipher_list
 * falls back to single-line a=crypto with default AES_CM_128_HMAC_SHA1_80
 * (sdp_crypto_offer behavior). The 46-byte master local_key is shared across
 * suite-lines (per-suite truncation via key+salt length); peer picks one suite
 * so unused suite-line key material is discarded immediately.
 *
 * \param p A valid sdp_crypto struct
 * \param cipher_list NULL or empty for default; comma-separated suite names otherwise
 *
 * \retval 0 success
 * \retval nonzero failure
 */
int sdp_crypto_offer_list(struct sdp_crypto *p, const char *cipher_list);


/*! \brief Return the a_crypto value of the sdp_crypto struct
 *
 * \param p An sdp_crypto struct that has had sdp_crypto_offer called
 *
 * \retval The value of the a_crypto for p
 */
const char *sdp_crypto_attrib(struct sdp_crypto *p);

#endif	/* _SOFIA_SDP_CRYPTO_H */
