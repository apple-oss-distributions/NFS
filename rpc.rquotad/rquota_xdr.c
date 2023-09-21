/*
 * Copyright (c) 2007 Apple Inc.  All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "rquota.h"
#include <sys/cdefs.h>
#ifndef __lint__
/*static char sccsid[] = "from: @(#)rquota.x 1.2 87/09/20 Copyr 1987 Sun Micro";*/
/*static char sccsid[] = "from: @(#)rquota.x	2.1 88/08/01 4.0 RPCSRC";*/
__RCSID("$NetBSD: rquota.x,v 1.6 2004/07/01 22:52:34 kleink Exp $");
#endif /* not __lint__ */

bool_t
xdr_getquota_args(XDR *xdrs, getquota_args *objp)
{
	if (!xdr_string(xdrs, &objp->gqa_pathp, RQ_PATHLEN)) {
		return FALSE;
	}
	if (!xdr_int(xdrs, &objp->gqa_uid)) {
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_ext_getquota_args(XDR *xdrs, ext_getquota_args *objp)
{
	if (!xdr_string(xdrs, &objp->gqa_pathp, RQ_PATHLEN)) {
		return FALSE;
	}
	if (!xdr_int(xdrs, &objp->gqa_type)) {
		return FALSE;
	}
	if (!xdr_int(xdrs, &objp->gqa_id)) {
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_rquota(XDR *xdrs, rquota *objp)
{
	int32_t *buf;

	if (xdrs->x_op == XDR_ENCODE) {
		buf = (int32_t *)XDR_INLINE(xdrs, 10 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_int(xdrs, &objp->rq_bsize)) {
				return FALSE;
			}
			if (!xdr_bool(xdrs, &objp->rq_active)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_bhardlimit)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_bsoftlimit)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_curblocks)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_fhardlimit)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_fsoftlimit)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_curfiles)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_btimeleft)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_ftimeleft)) {
				return FALSE;
			}
		} else {
			IXDR_PUT_LONG(buf, objp->rq_bsize);
			IXDR_PUT_BOOL(buf, objp->rq_active);
			IXDR_PUT_U_LONG(buf, objp->rq_bhardlimit);
			IXDR_PUT_U_LONG(buf, objp->rq_bsoftlimit);
			IXDR_PUT_U_LONG(buf, objp->rq_curblocks);
			IXDR_PUT_U_LONG(buf, objp->rq_fhardlimit);
			IXDR_PUT_U_LONG(buf, objp->rq_fsoftlimit);
			IXDR_PUT_U_LONG(buf, objp->rq_curfiles);
			IXDR_PUT_U_LONG(buf, objp->rq_btimeleft);
			IXDR_PUT_U_LONG(buf, objp->rq_ftimeleft);
		}
	} else if (xdrs->x_op == XDR_DECODE) {
		buf = (int32_t *)XDR_INLINE(xdrs, 10 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_int(xdrs, &objp->rq_bsize)) {
				return FALSE;
			}
			if (!xdr_bool(xdrs, &objp->rq_active)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_bhardlimit)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_bsoftlimit)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_curblocks)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_fhardlimit)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_fsoftlimit)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_curfiles)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_btimeleft)) {
				return FALSE;
			}
			if (!xdr_u_int(xdrs, &objp->rq_ftimeleft)) {
				return FALSE;
			}
		} else {
			objp->rq_bsize = IXDR_GET_LONG(buf);
			objp->rq_active = IXDR_GET_BOOL(buf);
			objp->rq_bhardlimit = IXDR_GET_U_LONG(buf);
			objp->rq_bsoftlimit = IXDR_GET_U_LONG(buf);
			objp->rq_curblocks = IXDR_GET_U_LONG(buf);
			objp->rq_fhardlimit = IXDR_GET_U_LONG(buf);
			objp->rq_fsoftlimit = IXDR_GET_U_LONG(buf);
			objp->rq_curfiles = IXDR_GET_U_LONG(buf);
			objp->rq_btimeleft = IXDR_GET_U_LONG(buf);
			objp->rq_ftimeleft = IXDR_GET_U_LONG(buf);
		}
	} else {
		if (!xdr_int(xdrs, &objp->rq_bsize)) {
			return FALSE;
		}
		if (!xdr_bool(xdrs, &objp->rq_active)) {
			return FALSE;
		}
		if (!xdr_u_int(xdrs, &objp->rq_bhardlimit)) {
			return FALSE;
		}
		if (!xdr_u_int(xdrs, &objp->rq_bsoftlimit)) {
			return FALSE;
		}
		if (!xdr_u_int(xdrs, &objp->rq_curblocks)) {
			return FALSE;
		}
		if (!xdr_u_int(xdrs, &objp->rq_fhardlimit)) {
			return FALSE;
		}
		if (!xdr_u_int(xdrs, &objp->rq_fsoftlimit)) {
			return FALSE;
		}
		if (!xdr_u_int(xdrs, &objp->rq_curfiles)) {
			return FALSE;
		}
		if (!xdr_u_int(xdrs, &objp->rq_btimeleft)) {
			return FALSE;
		}
		if (!xdr_u_int(xdrs, &objp->rq_ftimeleft)) {
			return FALSE;
		}
	}
	return TRUE;
}

bool_t
xdr_gqr_status(XDR *xdrs, gqr_status *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)objp)) {
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_getquota_rslt(XDR *xdrs, getquota_rslt *objp)
{
	if (!xdr_gqr_status(xdrs, &objp->status)) {
		return FALSE;
	}
	switch (objp->status) {
	case Q_OK:
		if (!xdr_rquota(xdrs, &objp->getquota_rslt_u.gqr_rquota)) {
			return FALSE;
		}
		break;
	case Q_NOQUOTA:
		break;
	case Q_EPERM:
		break;
	default:
		return FALSE;
	}
	return TRUE;
}
