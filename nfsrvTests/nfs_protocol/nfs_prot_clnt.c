/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include <memory.h>
#include "nfs_prot.h"
#ifndef lint
/*static char sccsid[] = "from: @(#)nfs_prot.x 1.2 87/10/12 Copyr 1987 Sun Micro";*/
/*static char sccsid[] = "from: @(#)nfs_prot.x	2.1 88/08/01 4.0 RPCSRC";*/
#endif /* not lint */
#include <sys/cdefs.h>
__RCSID("$FreeBSD: src/include/rpcsvc/nfs_prot.x,v 1.8 2003/05/04 02:51:42 obrien Exp $");

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

void *
nfsproc_null_2(void *argp, CLIENT *clnt)
{
	static char clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_NULL, (xdrproc_t)xdr_void, argp, (xdrproc_t)xdr_void, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return (void *)&clnt_res;
}

attrstat *
nfsproc_getattr_2(nfs_fh *argp, CLIENT *clnt)
{
	static attrstat clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_GETATTR, (xdrproc_t)xdr_nfs_fh, argp, (xdrproc_t)xdr_attrstat, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

attrstat *
nfsproc_setattr_2(sattrargs *argp, CLIENT *clnt)
{
	static attrstat clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_SETATTR, (xdrproc_t)xdr_sattrargs, argp, (xdrproc_t)xdr_attrstat, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

void *
nfsproc_root_2(void *argp, CLIENT *clnt)
{
	static char clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_ROOT, (xdrproc_t)xdr_void, argp, (xdrproc_t)xdr_void, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return (void *)&clnt_res;
}

diropres *
nfsproc_lookup_2(diropargs *argp, CLIENT *clnt)
{
	static diropres clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_LOOKUP, (xdrproc_t)xdr_diropargs, argp, (xdrproc_t)xdr_diropres, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

readlinkres *
nfsproc_readlink_2(nfs_fh *argp, CLIENT *clnt)
{
	static readlinkres clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_READLINK, (xdrproc_t)xdr_nfs_fh, argp, (xdrproc_t)xdr_readlinkres, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

readres *
nfsproc_read_2(readargs *argp, CLIENT *clnt)
{
	static readres clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_READ, (xdrproc_t)xdr_readargs, argp, (xdrproc_t)xdr_readres, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

void *
nfsproc_writecache_2(void *argp, CLIENT *clnt)
{
	static char clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_WRITECACHE, (xdrproc_t)xdr_void, argp, (xdrproc_t)xdr_void, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return (void *)&clnt_res;
}

attrstat *
nfsproc_write_2(writeargs *argp, CLIENT *clnt)
{
	static attrstat clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_WRITE, (xdrproc_t)xdr_writeargs, argp, (xdrproc_t)xdr_attrstat, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

diropres *
nfsproc_create_2(createargs *argp, CLIENT *clnt)
{
	static diropres clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_CREATE, (xdrproc_t)xdr_createargs, argp, (xdrproc_t)xdr_diropres, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

nfsstat *
nfsproc_remove_2(diropargs *argp, CLIENT *clnt)
{
	static nfsstat clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_REMOVE, (xdrproc_t)xdr_diropargs, argp, (xdrproc_t)xdr_nfsstat, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

nfsstat *
nfsproc_rename_2(renameargs *argp, CLIENT *clnt)
{
	static nfsstat clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_RENAME, (xdrproc_t)xdr_renameargs, argp, (xdrproc_t)xdr_nfsstat, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

nfsstat *
nfsproc_link_2(linkargs *argp, CLIENT *clnt)
{
	static nfsstat clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_LINK, (xdrproc_t)xdr_linkargs, argp, (xdrproc_t)xdr_nfsstat, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

nfsstat *
nfsproc_symlink_2(symlinkargs *argp, CLIENT *clnt)
{
	static nfsstat clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_SYMLINK, (xdrproc_t)xdr_symlinkargs, argp, (xdrproc_t)xdr_nfsstat, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

diropres *
nfsproc_mkdir_2(createargs *argp, CLIENT *clnt)
{
	static diropres clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_MKDIR, (xdrproc_t)xdr_createargs, argp, (xdrproc_t)xdr_diropres, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

nfsstat *
nfsproc_rmdir_2(diropargs *argp, CLIENT *clnt)
{
	static nfsstat clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_RMDIR, (xdrproc_t)xdr_diropargs, argp, (xdrproc_t)xdr_nfsstat, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

readdirres *
nfsproc_readdir_2(readdirargs *argp, CLIENT *clnt)
{
	static readdirres clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_READDIR, (xdrproc_t)xdr_readdirargs, argp, (xdrproc_t)xdr_readdirres, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

statfsres *
nfsproc_statfs_2(nfs_fh *argp, CLIENT *clnt)
{
	static statfsres clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC_STATFS, (xdrproc_t)xdr_nfs_fh, argp, (xdrproc_t)xdr_statfsres, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

void *
nfsproc3_null_3(void *argp, CLIENT *clnt)
{
	static char clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_NULL, (xdrproc_t)xdr_void, argp, (xdrproc_t)xdr_void, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return (void *)&clnt_res;
}

GETATTR3res *
nfsproc3_getattr_3(GETATTR3args *argp, CLIENT *clnt)
{
	static GETATTR3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_GETATTR, (xdrproc_t)xdr_GETATTR3args, argp, (xdrproc_t)xdr_GETATTR3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

SETATTR3res *
nfsproc3_setattr_3(SETATTR3args *argp, CLIENT *clnt)
{
	static SETATTR3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_SETATTR, (xdrproc_t)xdr_SETATTR3args, argp, (xdrproc_t)xdr_SETATTR3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

LOOKUP3res *
nfsproc3_lookup_3(LOOKUP3args *argp, CLIENT *clnt)
{
	static LOOKUP3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_LOOKUP, (xdrproc_t)xdr_LOOKUP3args, argp, (xdrproc_t)xdr_LOOKUP3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

ACCESS3res *
nfsproc3_access_3(ACCESS3args *argp, CLIENT *clnt)
{
	static ACCESS3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_ACCESS, (xdrproc_t)xdr_ACCESS3args, argp, (xdrproc_t)xdr_ACCESS3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

READLINK3res *
nfsproc3_readlink_3(READLINK3args *argp, CLIENT *clnt)
{
	static READLINK3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_READLINK, (xdrproc_t)xdr_READLINK3args, argp, (xdrproc_t)xdr_READLINK3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

READ3res *
nfsproc3_read_3(READ3args *argp, CLIENT *clnt)
{
	static READ3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_READ, (xdrproc_t)xdr_READ3args, argp, (xdrproc_t)xdr_READ3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

WRITE3res *
nfsproc3_write_3(WRITE3args *argp, CLIENT *clnt)
{
	static WRITE3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_WRITE, (xdrproc_t)xdr_WRITE3args, argp, (xdrproc_t)xdr_WRITE3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

CREATE3res *
nfsproc3_create_3(CREATE3args *argp, CLIENT *clnt)
{
	static CREATE3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_CREATE, (xdrproc_t)xdr_CREATE3args, argp, (xdrproc_t)xdr_CREATE3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

MKDIR3res *
nfsproc3_mkdir_3(MKDIR3args *argp, CLIENT *clnt)
{
	static MKDIR3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_MKDIR, (xdrproc_t)xdr_MKDIR3args, argp, (xdrproc_t)xdr_MKDIR3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

SYMLINK3res *
nfsproc3_symlink_3(SYMLINK3args *argp, CLIENT *clnt)
{
	static SYMLINK3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_SYMLINK, (xdrproc_t)xdr_SYMLINK3args, argp, (xdrproc_t)xdr_SYMLINK3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

MKNOD3res *
nfsproc3_mknod_3(MKNOD3args *argp, CLIENT *clnt)
{
	static MKNOD3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_MKNOD, (xdrproc_t)xdr_MKNOD3args, argp, (xdrproc_t)xdr_MKNOD3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

REMOVE3res *
nfsproc3_remove_3(REMOVE3args *argp, CLIENT *clnt)
{
	static REMOVE3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_REMOVE, (xdrproc_t)xdr_REMOVE3args, argp, (xdrproc_t)xdr_REMOVE3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

RMDIR3res *
nfsproc3_rmdir_3(RMDIR3args *argp, CLIENT *clnt)
{
	static RMDIR3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_RMDIR, (xdrproc_t)xdr_RMDIR3args, argp, (xdrproc_t)xdr_RMDIR3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

RENAME3res *
nfsproc3_rename_3(RENAME3args *argp, CLIENT *clnt)
{
	static RENAME3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_RENAME, (xdrproc_t)xdr_RENAME3args, argp, (xdrproc_t)xdr_RENAME3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

LINK3res *
nfsproc3_link_3(LINK3args *argp, CLIENT *clnt)
{
	static LINK3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_LINK, (xdrproc_t)xdr_LINK3args, argp, (xdrproc_t)xdr_LINK3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

READDIR3res *
nfsproc3_readdir_3(READDIR3args *argp, CLIENT *clnt)
{
	static READDIR3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_READDIR, (xdrproc_t)xdr_READDIR3args, argp, (xdrproc_t)xdr_READDIR3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

READDIRPLUS3res *
nfsproc3_readdirplus_3(READDIRPLUS3args *argp, CLIENT *clnt)
{
	static READDIRPLUS3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_READDIRPLUS, (xdrproc_t)xdr_READDIRPLUS3args, argp, (xdrproc_t)xdr_READDIRPLUS3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

FSSTAT3res *
nfsproc3_fsstat_3(FSSTAT3args *argp, CLIENT *clnt)
{
	static FSSTAT3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_FSSTAT, (xdrproc_t)xdr_FSSTAT3args, argp, (xdrproc_t)xdr_FSSTAT3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

FSINFO3res *
nfsproc3_fsinfo_3(FSINFO3args *argp, CLIENT *clnt)
{
	static FSINFO3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_FSINFO, (xdrproc_t)xdr_FSINFO3args, argp, (xdrproc_t)xdr_FSINFO3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

PATHCONF3res *
nfsproc3_pathconf_3(PATHCONF3args *argp, CLIENT *clnt)
{
	static PATHCONF3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_PATHCONF, (xdrproc_t)xdr_PATHCONF3args, argp, (xdrproc_t)xdr_PATHCONF3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}

COMMIT3res *
nfsproc3_commit_3(COMMIT3args *argp, CLIENT *clnt)
{
	static COMMIT3res clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, NFSPROC3_COMMIT, (xdrproc_t)xdr_COMMIT3args, argp, (xdrproc_t)xdr_COMMIT3res, &clnt_res, TIMEOUT) != RPC_SUCCESS) {
		return NULL;
	}
	return &clnt_res;
}