/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _RQUOTA_H_RPCGEN
#define _RQUOTA_H_RPCGEN

#define RPCGEN_VERSION  199506

#include <oncrpc/rpc.h>

#define RQ_PATHLEN 1024

struct getquota_args {
	char *gqa_pathp;
	int gqa_uid;
};
typedef struct getquota_args getquota_args;
#ifdef __cplusplus
extern "C" bool_t xdr_getquota_args(XDR *, getquota_args*);
#elif __STDC__
extern  bool_t xdr_getquota_args(XDR *, getquota_args*);
#else /* Old Style C */
bool_t xdr_getquota_args();
#endif /* Old Style C */

#define RQUOTA_MAXQUOTAS 0x02
#define RQUOTA_USRQUOTA 0x00
#define RQUOTA_GRPQUOTA 0x01

struct ext_getquota_args {
	char *gqa_pathp;
	int gqa_type;
	int gqa_id;
};
typedef struct ext_getquota_args ext_getquota_args;
#ifdef __cplusplus
extern "C" bool_t xdr_ext_getquota_args(XDR *, ext_getquota_args*);
#elif __STDC__
extern  bool_t xdr_ext_getquota_args(XDR *, ext_getquota_args*);
#else /* Old Style C */
bool_t xdr_ext_getquota_args();
#endif /* Old Style C */


struct rquota {
	int rq_bsize;
	bool_t rq_active;
	u_int rq_bhardlimit;
	u_int rq_bsoftlimit;
	u_int rq_curblocks;
	u_int rq_fhardlimit;
	u_int rq_fsoftlimit;
	u_int rq_curfiles;
	u_int rq_btimeleft;
	u_int rq_ftimeleft;
};
typedef struct rquota rquota;
#ifdef __cplusplus
extern "C" bool_t xdr_rquota(XDR *, rquota*);
#elif __STDC__
extern  bool_t xdr_rquota(XDR *, rquota*);
#else /* Old Style C */
bool_t xdr_rquota();
#endif /* Old Style C */


enum gqr_status {
	Q_OK = 1,
	Q_NOQUOTA = 2,
	Q_EPERM = 3,
};
typedef enum gqr_status gqr_status;
#ifdef __cplusplus
extern "C" bool_t xdr_gqr_status(XDR *, gqr_status*);
#elif __STDC__
extern  bool_t xdr_gqr_status(XDR *, gqr_status*);
#else /* Old Style C */
bool_t xdr_gqr_status();
#endif /* Old Style C */


struct getquota_rslt {
	gqr_status status;
	union {
		rquota gqr_rquota;
	} getquota_rslt_u;
};
typedef struct getquota_rslt getquota_rslt;
#ifdef __cplusplus
extern "C" bool_t xdr_getquota_rslt(XDR *, getquota_rslt*);
#elif __STDC__
extern  bool_t xdr_getquota_rslt(XDR *, getquota_rslt*);
#else /* Old Style C */
bool_t xdr_getquota_rslt();
#endif /* Old Style C */


#define RQUOTAPROG ((rpc_uint)100011)
#define RQUOTAVERS ((rpc_uint)1)

#ifdef __cplusplus
#define RQUOTAPROC_NULL ((rpc_uint)0)
extern "C" void * rquotaproc_null_1(void *, CLIENT *);
extern "C" void * rquotaproc_null_1_svc(void *, struct svc_req *);
#define RQUOTAPROC_GETQUOTA ((rpc_uint)1)
extern "C" getquota_rslt * rquotaproc_getquota_1(getquota_args *, CLIENT *);
extern "C" getquota_rslt * rquotaproc_getquota_1_svc(getquota_args *, struct svc_req *);
#define RQUOTAPROC_GETACTIVEQUOTA ((rpc_uint)2)
extern "C" getquota_rslt * rquotaproc_getactivequota_1(getquota_args *, CLIENT *);
extern "C" getquota_rslt * rquotaproc_getactivequota_1_svc(getquota_args *, struct svc_req *);

#elif __STDC__
#define RQUOTAPROC_NULL ((rpc_uint)0)
extern  void * rquotaproc_null_1(void *, CLIENT *);
extern  void * rquotaproc_null_1_svc(void *, struct svc_req *);
#define RQUOTAPROC_GETQUOTA ((rpc_uint)1)
extern  getquota_rslt * rquotaproc_getquota_1(getquota_args *, CLIENT *);
extern  getquota_rslt * rquotaproc_getquota_1_svc(getquota_args *, struct svc_req *);
#define RQUOTAPROC_GETACTIVEQUOTA ((rpc_uint)2)
extern  getquota_rslt * rquotaproc_getactivequota_1(getquota_args *, CLIENT *);
extern  getquota_rslt * rquotaproc_getactivequota_1_svc(getquota_args *, struct svc_req *);

#else /* Old Style C */
#define RQUOTAPROC_NULL ((rpc_uint)0)
extern  void * rquotaproc_null_1();
extern  void * rquotaproc_null_1_svc();
#define RQUOTAPROC_GETQUOTA ((rpc_uint)1)
extern  getquota_rslt * rquotaproc_getquota_1();
extern  getquota_rslt * rquotaproc_getquota_1_svc();
#define RQUOTAPROC_GETACTIVEQUOTA ((rpc_uint)2)
extern  getquota_rslt * rquotaproc_getactivequota_1();
extern  getquota_rslt * rquotaproc_getactivequota_1_svc();
#endif /* Old Style C */
#define EXT_RQUOTAVERS ((rpc_uint)2)

#ifdef __cplusplus
extern "C" void * rquotaproc_null_2(void *, CLIENT *);
extern "C" void * rquotaproc_null_2_svc(void *, struct svc_req *);
extern "C" getquota_rslt * rquotaproc_getquota_2(ext_getquota_args *, CLIENT *);
extern "C" getquota_rslt * rquotaproc_getquota_2_svc(ext_getquota_args *, struct svc_req *);
extern "C" getquota_rslt * rquotaproc_getactivequota_2(ext_getquota_args *, CLIENT *);
extern "C" getquota_rslt * rquotaproc_getactivequota_2_svc(ext_getquota_args *, struct svc_req *);

#elif __STDC__
extern  void * rquotaproc_null_2(void *, CLIENT *);
extern  void * rquotaproc_null_2_svc(void *, struct svc_req *);
extern  getquota_rslt * rquotaproc_getquota_2(ext_getquota_args *, CLIENT *);
extern  getquota_rslt * rquotaproc_getquota_2_svc(ext_getquota_args *, struct svc_req *);
extern  getquota_rslt * rquotaproc_getactivequota_2(ext_getquota_args *, CLIENT *);
extern  getquota_rslt * rquotaproc_getactivequota_2_svc(ext_getquota_args *, struct svc_req *);

#else /* Old Style C */
extern  void * rquotaproc_null_2();
extern  void * rquotaproc_null_2_svc();
extern  getquota_rslt * rquotaproc_getquota_2();
extern  getquota_rslt * rquotaproc_getquota_2_svc();
extern  getquota_rslt * rquotaproc_getactivequota_2();
extern  getquota_rslt * rquotaproc_getactivequota_2_svc();
#endif /* Old Style C */

#endif /* !_RQUOTA_H_RPCGEN */
