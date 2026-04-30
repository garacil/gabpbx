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

/*! \file sip_srtp.h
 *
 * \brief SIP Secure RTP (SRTP)
 *
 * Specified in RFC 3711
 *
 * \author Mikael Magnusson <mikma@users.sourceforge.net>
 */

#ifndef _SIP_SRTP_H
#define _SIP_SRTP_H

#include "sdp_crypto.h"

/* SRTP flags */
#define SRTP_ENCR_OPTIONAL	(1 << 1)	/* SRTP encryption optional */
#define SRTP_CRYPTO_ENABLE	(1 << 2)
#define SRTP_CRYPTO_OFFER_OK	(1 << 3)

/*! \brief structure for secure RTP audio */
struct sip_srtp {
	unsigned int flags;
	struct sdp_crypto *crypto;
};

/*!
 * \brief allocate a sip_srtp structure
 * \retval a new malloc'd sip_srtp structure on success
 * \retval NULL on failure
*/
struct sip_srtp *sip_srtp_alloc(void);

/*!
 * \brief free a sip_srtp structure
 * \param srtp a sip_srtp structure
*/
void sip_srtp_destroy(struct sip_srtp *srtp);

#endif	/* _SIP_SRTP_H */
