
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "passwd_query.h"

const char *null_alt(const char *str, const char *alt)
{
	if ( str != NULL )
		return str;
	else
		return alt;
}

// This function is not as well generalized or factored as the others.
// Nonetheless, I am keeping it around because it most closely reflects
// the example code in the documentation.
void print_info(const char *login_name)
{
#define OOM_MESSAGE  ("Out of memory error while attempting to retrieve passwd entry for user %s\n")
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;
	int     err = -1;

	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	while ( err != 0 )
	{
		err = nfsutil_pw_query_call_getpwnam_r(&passwd_query, login_name);
		if ( err == EINTR )
			continue;
		else
		if ( err == ENOMEM ) {
			printf(OOM_MESSAGE, login_name);
			nfsutil_pw_query_cleanup(&passwd_query);
			return;
		}
		else
		if ( err == EIO ) {
			printf("I/O error during getpwnam_r: %s\n", strerror(err));
			nfsutil_pw_query_cleanup(&passwd_query);
			return;
		}
		else
		if ( err != 0 )
		{
			printf("Unhandled error from getpwnam_r: %s\n", strerror(err));
			nfsutil_pw_query_cleanup(&passwd_query);
			return;
		}
		//... etc ...
	}

	struct passwd  *pw;
	pw = nfsutil_pw_query_result(&passwd_query);
	if ( pw == NULL )
		printf("passwd entry not found for user '%s'\n", login_name);
	else
	{
		printf("passwd entry for '%s':\n", login_name);
		printf("  name:  %s\n", null_alt(pw->pw_name, "<NULL>"));
		printf("  uid:   %d\n", pw->pw_uid);
		printf("  gid:   %d\n", pw->pw_gid);
		printf("  dir:   %s\n", null_alt(pw->pw_dir, "<NULL>"));
		printf("  shell: %s\n", null_alt(pw->pw_shell, "<NULL>"));
		// ... do things with `pw` ...
	}

	nfsutil_pw_query_cleanup(&passwd_query);
	// Everything should be done by this point; `pw` is now invalid.

	return;
#undef OOM_MESSAGE
}

#define  RESPONSE_SUCCESS  (0)
#define  RESPONSE_ABORT    (1)
#define  RESPONSE_RETRY    (2)

int handle_errors(int pwgrp_return_code, const char *function_name)
{
	int err = pwgrp_return_code;
	if ( err == 0 )
		return RESPONSE_SUCCESS;
	if ( err == EINTR )
		return RESPONSE_RETRY;

	if ( err == EIO )
		printf("I/O error during %s: %s\n", function_name, strerror(err));
	else
		printf("Unhandled error from %s: %s\n", function_name, strerror(err));

	return RESPONSE_ABORT;
}

#define  HANDLE_ERRORS(return_code, cleanup_stmt) \
	int response = handle_errors(err, __FUNCTION__); \
	if ( response == RESPONSE_RETRY ) \
		continue; \
	else \
	if ( response == RESPONSE_ABORT ) \
	{ \
		cleanup_stmt; \
		return; \
	} \
	else \
	if ( response == RESPONSE_SUCCESS ) \
		break; \
	else \
	{ \
		printf("Invalid return code %d from 'handle_errors(%d)'.", response, err); \
		cleanup_stmt; \
		return; \
	}

void print_group(struct  nfsutil_group_query  group_query, const char *key)
{
	struct group  *grp;
	grp = nfsutil_grp_query_result(&group_query);
	if ( grp == NULL )
		printf("group entry not found for group '%s'\n", key);
	else
	{
		printf("group entry for '%s':\n", key);
		printf("  name:     %s\n", null_alt(grp->gr_name, "<NULL>"));
		printf("  gid:      %d\n", grp->gr_gid);
		char **members = grp->gr_mem;
		for ( ssize_t i = 0; members[i] != NULL; i++ )
		{
			const char *member = members[i];
			printf("  member[%ld]: %s\n", i, member);
		}
	}
}

void print_group_from_name(const char *group_name)
{
	char    bufptr[GROUP_STACKMEM_SIZE_HINT];
	size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
	struct  nfsutil_group_query  group_query;
	int     err = -1;

	nfsutil_grp_query_init(&group_query, bufptr, buflen);

	while ( err != 0 )
	{
		err = nfsutil_grp_query_call_getgrnam_r(&group_query, group_name);
		if ( err == ENOMEM )
		{
			printf("Out of memory error while attempting to retrieve group entry for group with name %s\n",
				group_name);
			nfsutil_grp_query_cleanup(&group_query);
			return;
		}
		HANDLE_ERRORS(err, nfsutil_grp_query_cleanup(&group_query))
	}

	print_group(group_query, group_name);
	nfsutil_grp_query_cleanup(&group_query);
}

void print_group_from_gid_2(gid_t gid, const char *gidstr)
{
	char    bufptr[GROUP_STACKMEM_SIZE_HINT];
	size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
	struct  nfsutil_group_query  group_query;
	int     err = -1;

	nfsutil_grp_query_init(&group_query, bufptr, buflen);

	while ( err != 0 )
	{
		err = nfsutil_grp_query_call_getgrgid_r(&group_query, gid);
		if ( err == ENOMEM )
		{
			printf("Out of memory error while attempting to retrieve group entry for group with ID %d\n", gid);
			nfsutil_grp_query_cleanup(&group_query);
			return;
		}
		HANDLE_ERRORS(err, nfsutil_grp_query_cleanup(&group_query))
	}

	print_group(group_query, gidstr);
	nfsutil_grp_query_cleanup(&group_query);
}

void print_group_from_gid(gid_t gid)
{
	char  fmtbuf[16];
	int rc = snprintf(fmtbuf, 16, "%d", gid);
	if ( rc >= 16 )
		fmtbuf[15] = '\0';
	const char *gidstr = fmtbuf;
	print_group_from_gid_2(gid, gidstr);
}

void print_passwd(struct  nfsutil_passwd_query  passwd_query, const char *key)
{
	struct passwd  *pw;
	pw = nfsutil_pw_query_result(&passwd_query);
	if ( pw == NULL )
		printf("passwd entry not found for user '%s'\n", key);
	else
	{
		printf("passwd entry for '%s':\n", key);
		printf("  name:  %s\n", null_alt(pw->pw_name, "<NULL>"));
		printf("  uid:   %d\n", pw->pw_uid);
		printf("  gid:   %d\n", pw->pw_gid);
		printf("  dir:   %s\n", null_alt(pw->pw_dir, "<NULL>"));
		printf("  shell: %s\n", null_alt(pw->pw_shell, "<NULL>"));
		// ... do things with `pw` ...

		printf("\n");
		print_group_from_gid(pw->pw_gid);
	}
}

void print_passwd_from_name(const char *login_name)
{
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;
	int     err = -1;

	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	while ( err != 0 )
	{
		err = nfsutil_pw_query_call_getpwnam_r(&passwd_query, login_name);
		if ( err == ENOMEM )
		{
			printf("Out of memory error while attempting to retrieve passwd entry for user %s\n",
				login_name);
			nfsutil_pw_query_cleanup(&passwd_query);
			return;
		}
		HANDLE_ERRORS(err, nfsutil_pw_query_cleanup(&passwd_query))
	}

	print_passwd(passwd_query, login_name);
	nfsutil_pw_query_cleanup(&passwd_query);
}

void print_passwd_from_uid_2(uid_t uid, const char *uidstr)
{
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;
	int     err = -1;

	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	while ( err != 0 )
	{
		err = nfsutil_pw_query_call_getpwuid_r(&passwd_query, uid);
		if ( err == ENOMEM )
		{
			printf("Out of memory error while attempting to retrieve passwd entry for user with ID %d\n", uid);
			nfsutil_pw_query_cleanup(&passwd_query);
			return;
		}
		HANDLE_ERRORS(err, nfsutil_pw_query_cleanup(&passwd_query))
	}

	print_passwd(passwd_query, uidstr);
	nfsutil_pw_query_cleanup(&passwd_query);
}

void print_passwd_from_uid(uid_t uid)
{
	char  fmtbuf[16];
	int rc = snprintf(fmtbuf, 16, "%d", uid);
	if ( rc >= 16 )
		fmtbuf[15] = '\0';
	const char *uidstr = fmtbuf;
	print_group_from_gid_2(uid, uidstr);
}

int prefix_match(const char *maybe_prefix, const char *full_text)
{
	for ( size_t i = 0;; i++ )
	{
		char  prechar = maybe_prefix[i];
		char  fuchar  = full_text[i];
		if ( prechar == '\0' || fuchar == '\0' )
			return i;

		if ( prechar != fuchar )
			return 0;
	}
	return -1;
}

ssize_t to_uint(const char *thing)
{
	if ( thing[0] == '0' && thing[1] == '\0' )
		return 0;

	ssize_t result = 0;
	for ( size_t i = 0; thing[i] != '\0'; i++ )
	{
		char ch = thing[i];
		if ( !('0' <= ch && ch <= '9') )
			return -1;

		result *= 10;
		result += (ch - '0');
	}
	return result;
}

int to_uint_arg(const char *thing, size_t *result)
{
	ssize_t intermediate;
	intermediate = to_uint(thing);
	if ( intermediate >= 0 )
	{
		*result = intermediate;
		return 1;
	}
	else
		return 0;
}

int main(int argc, const char **argv)
{
	size_t id;

	if ( argc == 2 )
		print_info(argv[1]);
		//print_info("chad");
	else
	if ( argc == 3 )
	{
		const char *table = argv[1];
		const char *key   = argv[2];
		if ( prefix_match(table, "passwd") )
		{
			if ( to_uint_arg(key, &id) )
			{
				uid_t  uid = id;
				print_passwd_from_uid(uid);
			}
			else
				print_passwd_from_name(key);
		}
		else
		if ( prefix_match(table, "group") )
		{
			if ( to_uint_arg(key, &id) )
			{
				gid_t  gid = id;
				print_group_from_gid(gid);
			}
			else
				print_group_from_name(key);
		}
		else
		{
			printf("ERROR: 1st argument must be either 'passwd' or 'group'.\n");
			return 1;
		}
	}
	else
	{
		printf("ERROR: Need one or two arguments.\n");
		printf("\n");
		printf("Usage:\n");
		printf("    pwgrp_test  [passwd|group]  [name|uid|gid]\n");
		printf("    pwgrp_test  [login_name]\n");
		printf("\n");
		return 1;
	}
	return 0;
}
