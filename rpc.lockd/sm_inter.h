/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _SM_INTER_H_RPCGEN
#define _SM_INTER_H_RPCGEN

#define RPCGEN_VERSION  199506

#include <oncrpc/rpc.h>

#define SM_MAXSTRLEN 1024

struct sm_name {
	char *mon_name;
};
typedef struct sm_name sm_name;
#ifdef __cplusplus
extern "C" bool_t xdr_sm_name(XDR *, sm_name*);
#elif __STDC__
extern  bool_t xdr_sm_name(XDR *, sm_name*);
#else /* Old Style C */
bool_t xdr_sm_name();
#endif /* Old Style C */


struct my_id {
	char *my_name;
	int my_prog;
	int my_vers;
	int my_proc;
};
typedef struct my_id my_id;
#ifdef __cplusplus
extern "C" bool_t xdr_my_id(XDR *, my_id*);
#elif __STDC__
extern  bool_t xdr_my_id(XDR *, my_id*);
#else /* Old Style C */
bool_t xdr_my_id();
#endif /* Old Style C */


struct mon_id {
	char *mon_name;
	struct my_id my_id;
};
typedef struct mon_id mon_id;
#ifdef __cplusplus
extern "C" bool_t xdr_mon_id(XDR *, mon_id*);
#elif __STDC__
extern  bool_t xdr_mon_id(XDR *, mon_id*);
#else /* Old Style C */
bool_t xdr_mon_id();
#endif /* Old Style C */


struct mon {
	struct mon_id mon_id;
	char priv[16];
};
typedef struct mon mon;
#ifdef __cplusplus
extern "C" bool_t xdr_mon(XDR *, mon*);
#elif __STDC__
extern  bool_t xdr_mon(XDR *, mon*);
#else /* Old Style C */
bool_t xdr_mon();
#endif /* Old Style C */


struct stat_chge {
	char *mon_name;
	int state;
};
typedef struct stat_chge stat_chge;
#ifdef __cplusplus
extern "C" bool_t xdr_stat_chge(XDR *, stat_chge*);
#elif __STDC__
extern  bool_t xdr_stat_chge(XDR *, stat_chge*);
#else /* Old Style C */
bool_t xdr_stat_chge();
#endif /* Old Style C */


struct sm_stat {
	int state;
};
typedef struct sm_stat sm_stat;
#ifdef __cplusplus
extern "C" bool_t xdr_sm_stat(XDR *, sm_stat*);
#elif __STDC__
extern  bool_t xdr_sm_stat(XDR *, sm_stat*);
#else /* Old Style C */
bool_t xdr_sm_stat();
#endif /* Old Style C */


enum sm_res {
	stat_succ = 0,
	stat_fail = 1,
};
typedef enum sm_res sm_res;
#ifdef __cplusplus
extern "C" bool_t xdr_sm_res(XDR *, sm_res*);
#elif __STDC__
extern  bool_t xdr_sm_res(XDR *, sm_res*);
#else /* Old Style C */
bool_t xdr_sm_res();
#endif /* Old Style C */


struct sm_stat_res {
	sm_res res_stat;
	int state;
};
typedef struct sm_stat_res sm_stat_res;
#ifdef __cplusplus
extern "C" bool_t xdr_sm_stat_res(XDR *, sm_stat_res*);
#elif __STDC__
extern  bool_t xdr_sm_stat_res(XDR *, sm_stat_res*);
#else /* Old Style C */
bool_t xdr_sm_stat_res();
#endif /* Old Style C */


struct sm_status {
	char *mon_name;
	int state;
	char priv[16];
};
typedef struct sm_status sm_status;
#ifdef __cplusplus
extern "C" bool_t xdr_sm_status(XDR *, sm_status*);
#elif __STDC__
extern  bool_t xdr_sm_status(XDR *, sm_status*);
#else /* Old Style C */
bool_t xdr_sm_status();
#endif /* Old Style C */


#define SM_PROG ((rpc_uint)100024)
#define SM_VERS ((rpc_uint)1)

#ifdef __cplusplus
#define SM_STAT ((rpc_uint)1)
extern "C" struct sm_stat_res * sm_stat_1(struct sm_name *, CLIENT *);
extern "C" struct sm_stat_res * sm_stat_1_svc(struct sm_name *, struct svc_req *);
#define SM_MON ((rpc_uint)2)
extern "C" struct sm_stat_res * sm_mon_1(struct mon *, CLIENT *);
extern "C" struct sm_stat_res * sm_mon_1_svc(struct mon *, struct svc_req *);
#define SM_UNMON ((rpc_uint)3)
extern "C" struct sm_stat * sm_unmon_1(struct mon_id *, CLIENT *);
extern "C" struct sm_stat * sm_unmon_1_svc(struct mon_id *, struct svc_req *);
#define SM_UNMON_ALL ((rpc_uint)4)
extern "C" struct sm_stat * sm_unmon_all_1(struct my_id *, CLIENT *);
extern "C" struct sm_stat * sm_unmon_all_1_svc(struct my_id *, struct svc_req *);
#define SM_SIMU_CRASH ((rpc_uint)5)
extern "C" void * sm_simu_crash_1(void *, CLIENT *);
extern "C" void * sm_simu_crash_1_svc(void *, struct svc_req *);
#define SM_NOTIFY ((rpc_uint)6)
extern "C" void * sm_notify_1(struct stat_chge *, CLIENT *);
extern "C" void * sm_notify_1_svc(struct stat_chge *, struct svc_req *);

#elif __STDC__
#define SM_STAT ((rpc_uint)1)
extern  struct sm_stat_res * sm_stat_1(struct sm_name *, CLIENT *);
extern  struct sm_stat_res * sm_stat_1_svc(struct sm_name *, struct svc_req *);
#define SM_MON ((rpc_uint)2)
extern  struct sm_stat_res * sm_mon_1(struct mon *, CLIENT *);
extern  struct sm_stat_res * sm_mon_1_svc(struct mon *, struct svc_req *);
#define SM_UNMON ((rpc_uint)3)
extern  struct sm_stat * sm_unmon_1(struct mon_id *, CLIENT *);
extern  struct sm_stat * sm_unmon_1_svc(struct mon_id *, struct svc_req *);
#define SM_UNMON_ALL ((rpc_uint)4)
extern  struct sm_stat * sm_unmon_all_1(struct my_id *, CLIENT *);
extern  struct sm_stat * sm_unmon_all_1_svc(struct my_id *, struct svc_req *);
#define SM_SIMU_CRASH ((rpc_uint)5)
extern  void * sm_simu_crash_1(void *, CLIENT *);
extern  void * sm_simu_crash_1_svc(void *, struct svc_req *);
#define SM_NOTIFY ((rpc_uint)6)
extern  void * sm_notify_1(struct stat_chge *, CLIENT *);
extern  void * sm_notify_1_svc(struct stat_chge *, struct svc_req *);

#else /* Old Style C */
#define SM_STAT ((rpc_uint)1)
extern  struct sm_stat_res * sm_stat_1();
extern  struct sm_stat_res * sm_stat_1_svc();
#define SM_MON ((rpc_uint)2)
extern  struct sm_stat_res * sm_mon_1();
extern  struct sm_stat_res * sm_mon_1_svc();
#define SM_UNMON ((rpc_uint)3)
extern  struct sm_stat * sm_unmon_1();
extern  struct sm_stat * sm_unmon_1_svc();
#define SM_UNMON_ALL ((rpc_uint)4)
extern  struct sm_stat * sm_unmon_all_1();
extern  struct sm_stat * sm_unmon_all_1_svc();
#define SM_SIMU_CRASH ((rpc_uint)5)
extern  void * sm_simu_crash_1();
extern  void * sm_simu_crash_1_svc();
#define SM_NOTIFY ((rpc_uint)6)
extern  void * sm_notify_1();
extern  void * sm_notify_1_svc();
#endif /* Old Style C */

#endif /* !_SM_INTER_H_RPCGEN */
