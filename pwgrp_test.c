
#include <errno.h>
#include <grp.h>
#include <limits.h> // NGROUPS_MAX
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "passwd_query.h"

// Call the given function until its return code (stored in the `err` macro
// parameter) is not equal to EINTR. This essentially retries the function
// whenever an interrupt causes it to exit.
#define EINTR_LOOP(err, function_expr) \
	do { err = (function_expr); } while (err == EINTR);

static const char *null_alt(const char *str, const char *alt)
{
	if ( str != NULL )
		return str;
	else
		return alt;
}

// These functions are not as well generalized or factored as the others.
// Nonetheless, I am keeping them around because they most closely reflect
// the example code in the documentation.
static void example_print_passwd(const char *login_name)
{
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
			printf("Out of memory error while attempting to retrieve passwd entry for user %s\n",
				login_name);
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
		//... etc ...
		if ( err != 0 )
		{
			printf("Unhandled error from getpwnam_r: %s\n", strerror(err));
			nfsutil_pw_query_cleanup(&passwd_query);
			return;
		}
	}

	struct passwd  *pw;
	pw = nfsutil_pw_query_result(&passwd_query);
	if ( pw == NULL )
		printf("passwd entry not found for user '%s'\n", login_name);
	else
	{
		// ... do things with `pw` ...
		printf("passwd entry for '%s':\n", login_name);
		printf("  name:  %s\n", null_alt(pw->pw_name, "<NULL>"));
		printf("  uid:   %d\n", pw->pw_uid);
		printf("  gid:   %d\n", pw->pw_gid);
		printf("  dir:   %s\n", null_alt(pw->pw_dir, "<NULL>"));
		printf("  shell: %s\n", null_alt(pw->pw_shell, "<NULL>"));
	}

	nfsutil_pw_query_cleanup(&passwd_query);
	// Everything should be done by this point; `pw` is now invalid.

	return;
}

static void example_print_group(const char *group_name)
{
	char    bufptr[GROUP_STACKMEM_SIZE_HINT];
	size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
	struct  nfsutil_group_query  group_query;
	int     err = -1;

	nfsutil_grp_query_init(&group_query, bufptr, buflen);

	while ( err != 0 )
	{
		err = nfsutil_grp_query_call_getgrnam_r(&group_query, group_name);
		if ( err == EINTR )
			continue;
		else
		if ( err == ENOMEM ) {
			printf("Out of memory error while attempting to retrieve group entry for group %s\n",
				group_name);
			nfsutil_grp_query_cleanup(&group_query);
			return;
		}
		else
		if ( err == EIO ) {
			printf("I/O error during getpwnam_r: %s\n", strerror(err));
			nfsutil_grp_query_cleanup(&group_query);
			return;
		}
		else
		//... etc ...
		if ( err != 0 )
		{
			printf("Unhandled error from getpwnam_r: %s\n", strerror(err));
			nfsutil_grp_query_cleanup(&group_query);
			return;
		}
	}

	struct group  *grp;
	grp = nfsutil_grp_query_result(&group_query);
	if ( grp == NULL )
		printf("group entry not found for group '%s'\n", group_name);
	else
	{
		// ... do things with `grp` ...
		printf("group entry for '%s':\n", group_name);
		printf("  name:     %s\n", null_alt(grp->gr_name, "<NULL>"));
		printf("  gid:      %d\n", grp->gr_gid);
		char **members = grp->gr_mem;
		for ( ssize_t i = 0; members[i] != NULL; i++ )
		{
			const char *member = members[i];
			printf("  member[%ld]: %s\n", i, null_alt(member, "<NULL>"));
		}
	}

	nfsutil_grp_query_cleanup(&group_query);
	// Everything should be done by this point; `grp` is now invalid.

	return;
}

void print_group(struct group *grp, const char *key)
{
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
			printf("  member[%ld]: %s\n", i, null_alt(member, "<NULL>"));
		}
	}
}

void print_group_ints(struct nfsutil_group_ints  grp_ints, const char *key)
{
	if ( grp_ints.err == ENOENT )
		printf("group entry not found for group '%s'\n", key);
	else
	if ( grp_ints.err )
		printf("group entry for group '%s' can't be retrieved due to errors.\n", key);
	else
	{
		printf("group entry (abridged) for '%s':\n", key);
		printf("  gid:   %d\n", grp_ints.gid);

		printf("\n");
	}
}

static int attempt_clone_group(
	struct group **grp,
	struct nfsutil_group_query group_query,
	const char *key)
{
	// We could have instead just called print_group like so:
	//print_group(group_query, group_name);
	// or
	//print_group(group_query, gidstr);
	//
	// But we should test our copying functions.
	// So let's try to persist the group object beyond cleanup:
	struct group *orig_grp = nfsutil_grp_query_result(&group_query);
	struct group *clone_grp;
	int err = nfsutil_clone_group(&clone_grp, orig_grp);

	if ( err )
	{
		// It didn't work, but we can still print some information (in addition
		// to the earlier error messages) using the still-valid original struct
		// that is allocated in the query instance.
		printf("\n");
		print_group(orig_grp, key);
		*grp = NULL;
		return err;
	}

	// If all went well, the caller will get around to calling 'print_group'
	// later on, after they have cleaned up the query object.
	*grp = clone_grp;
	return err;
}

void print_group_from_name(const char *group_name)
{
	char    bufptr[GROUP_STACKMEM_SIZE_HINT];
	size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
	struct  nfsutil_group_query  group_query;

	nfsutil_grp_query_init(&group_query, bufptr, buflen);

	int err;
	do {
		err = nfsutil_grp_query_call_getgrnam_r(&group_query, group_name);
	} while ( err == EINTR );

	struct group *grp;
	int oom = attempt_clone_group(&grp, group_query, group_name);
	if ( oom )
		err = oom;

	nfsutil_grp_query_cleanup(&group_query);

	// If the cloning was successful, then we now have a mallocated group
	// object that we should print and then free.
	if ( err )
		nfsidmap_print_pwgrp_error(err, "print_group_from_name", "group name", group_name, "", "", "");
	else {
		print_group(grp, group_name);
		if ( grp )
			free(grp);
	}
}

void print_group_from_gid_2(gid_t gid, const char *gidstr)
{
	char    bufptr[GROUP_STACKMEM_SIZE_HINT];
	size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
	struct  nfsutil_group_query  group_query;

	nfsutil_grp_query_init(&group_query, bufptr, buflen);

	int err;
	do {
		err = nfsutil_grp_query_call_getgrgid_r(&group_query, gid);
	} while ( err == EINTR );

	struct group *grp;
	int oom = attempt_clone_group(&grp, group_query, gidstr);
	if ( oom )
		err = oom;

	nfsutil_grp_query_cleanup(&group_query);

	// If the cloning was successful, then we now have a mallocated group
	// object that we should print and then free.
	if ( err )
		nfsidmap_print_pwgrp_error(err, "print_group_from_gid", "group with ID", gidstr, "", "", "");
	else {
		print_group(grp, gidstr);
		if ( grp )
			free(grp);
	}
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

void print_passwd(struct passwd *pw, const char *key)
{
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

void print_passwd_ints(struct nfsutil_passwd_ints  pw_ints, const char *key)
{
	if ( pw_ints.err == ENOENT )
		printf("passwd entry not found for user '%s'\n", key);
	else
	if ( pw_ints.err )
		printf("passwd entry for user '%s' can't be retrieved due to errors.\n", key);
	else
	{
		printf("passwd entry (abridged) for '%s':\n", key);
		printf("  uid:   %d\n", pw_ints.uid);
		printf("  gid:   %d\n", pw_ints.gid);

		printf("\n");
	}
}

static int attempt_clone_passwd(
	struct passwd **pw,
	struct nfsutil_passwd_query passwd_query,
	const char *key)
{
	// We could have instead just called print_passwd like so:
	//print_passwd(passwd_query, login_name);
	// or
	//print_passwd(passwd_query, uidstr);
	//
	// But we should test our copying functions.
	// So let's try to persist the passwd object beyond cleanup:
	struct passwd *orig_pw = nfsutil_pw_query_result(&passwd_query);
	struct passwd *clone_pw;
	int err = nfsutil_clone_passwd(&clone_pw, orig_pw);
	if ( err == ENOMEM )
		printf("Out of memory error while cloning the 'passwd' struct for user '%s'.\n", key);
	else if ( err != 0 )
		printf("Unknown error while cloning the 'passwd' struct for user '%s'.\n", key);

	if ( err )
	{
		// It didn't work, but we can still print some information (in addition
		// to the earlier error messages) using the still-valid original struct
		// that is allocated in the query instance.
		printf("\n");
		print_passwd(orig_pw, key);
		*pw = NULL;
		return err;
	}

	// If all went well, the caller will get around to calling 'print_passwd'
	// later on, after they have cleaned up the query object.
	*pw = clone_pw;
	return err;
}

void print_passwd_from_name(const char *login_name)
{
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;

	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	int err;
	do {
		err = nfsutil_pw_query_call_getpwnam_r(&passwd_query, login_name);
	} while ( err == EINTR );

	struct passwd *pw;
	int oom = attempt_clone_passwd(&pw, passwd_query, login_name);
	if ( oom )
		err = oom;

	nfsutil_pw_query_cleanup(&passwd_query);

	// If the cloning was successful, then we now have a mallocated passwd
	// object that we should print and then free.
	if ( err )
		nfsidmap_print_pwgrp_error(err, "print_passwd_from_name", "user name", login_name, "", "", "");
	else {
		print_passwd(pw, login_name);
		if ( pw )
			free(pw);
	}
}

void print_passwd_from_uid_2(uid_t uid, const char *uidstr)
{
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;

	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	int err;
	do {
		err = nfsutil_pw_query_call_getpwuid_r(&passwd_query, uid);
	} while ( err == EINTR );

	struct passwd *pw;
	int oom = attempt_clone_passwd(&pw, passwd_query, uidstr);
	if ( oom )
		err = oom;

	nfsutil_pw_query_cleanup(&passwd_query);

	// If the cloning was successful, then we now have a mallocated passwd
	// object that we should print and then free.
	if ( err )
		nfsidmap_print_pwgrp_error(err, "print_passwd_from_uid", "user with ID", uidstr, "", "", "");
	else {
		print_passwd(pw, uidstr);
		if ( pw )
			free(pw);
	}
}

void print_passwd_from_uid(uid_t uid)
{
	char  fmtbuf[16];
	int rc = snprintf(fmtbuf, 16, "%d", uid);
	if ( rc >= 16 )
		fmtbuf[15] = '\0';
	const char *uidstr = fmtbuf;
	print_passwd_from_uid_2(uid, uidstr);
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

	test__format_expansion_length();
	test__escape_fmtspec_inplace();

	if ( argc == 2 )
		//example_print_passwd(argv[1]);
		example_print_group(argv[1]);
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
		if ( prefix_match(table, "grouplist") )
		{
			const char *key_desc = "";
			struct nfsutil_passwd_ints  pw_ints;
			if ( to_uint_arg(key, &id) )
			{
				uid_t  uid = id;
				pw_ints = nfsutil_getpwuid_ints(uid);
				key_desc = "user with uid";
			}
			else
			{
				pw_ints = nfsutil_getpwnam_ints(key);
				key_desc = "user name";
			}

			int err = pw_ints.err;
			if ( err )
				nfsidmap_print_pwgrp_error(err, "pwgrp_test grouplist",
					key_desc, key, "", "", "");
			else
			{
				uid_t user_uid = pw_ints.uid;
				gid_t user_gid = pw_ints.gid;
				gid_t groups_buf[NGROUPS_MAX+1];
				int   ngroups = NGROUPS_MAX+1;
				gid_t *groups = groups_buf;
				int need_free = 0;
				EINTR_LOOP(err, nfsutil_getgrouplist_by_uid(user_uid, user_gid, groups, &ngroups));
				if ( err == ERANGE )
				{
					groups = malloc(ngroups * sizeof(gid_t));
					EINTR_LOOP(err, nfsutil_getgrouplist_by_uid(user_uid, user_gid, groups, &ngroups));
					need_free = 1;
				}

				if ( err )
					nfsidmap_print_pwgrp_error(err, "pwgrp_test grouplist",
						key_desc, key, "", "", "");
				else {
					printf("Grouplist for %s '%s':\n", key_desc, key);
					size_t i;
					for ( i = 0; i < ngroups; i++ )
						printf("  %d\n", groups[i]);
					printf("\n");
				}

				if ( need_free )
					free(groups);
			}
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
			printf("ERROR: 1st argument must be either 'passwd', 'group', or 'grouplist'.\n");
			return 1;
		}
	}
	else
	if ( argc == 4 )
	{
		const char *table = argv[1];
		const char *reqs  = argv[2];
		const char *key   = argv[3];

		if ( prefix_match(table, "passwd") )
		{
			int err;
			if ( prefix_match(reqs, "ints") )
			{
				struct nfsutil_passwd_ints pw_ints;
				if ( to_uint_arg(key, &id) )
				{
					uid_t  uid = id;
					pw_ints = nfsutil_getpwuid_ints(uid);
					err = pw_ints.err;
					if ( err )
						nfsidmap_print_pwgrp_error(err, "pwgrp_test passwd ints", "user with ID", key, "", "", "");
				}
				else
				{
					pw_ints = nfsutil_getpwnam_ints(key);
					err = pw_ints.err;
					if ( err )
						nfsidmap_print_pwgrp_error(err, "pwgrp_test passwd ints", "user name", key, "", "", "");
				}

				if ( !err )
					print_passwd_ints(pw_ints, key);
			}
			else
			if ( prefix_match(reqs, "struct") )
			{
				struct passwd *pw;
				if ( to_uint_arg(key, &id) )
				{
					uid_t  uid = id;
					err = nfsutil_getpwuid_struct(&pw, uid);
					if ( err )
						nfsidmap_print_pwgrp_error(err, "pwgrp_test passwd struct", "user with ID", key, "", "", "");
				}
				else
				{
					err = nfsutil_getpwnam_struct(&pw, key);
					if ( err )
						nfsidmap_print_pwgrp_error(err, "pwgrp_test passwd struct", "user name", key, "", "", "");
				}

				if ( !err )
					print_passwd(pw, key);
			}
			else
			{
				printf("ERROR: 2nd argument must be either 'ints' or 'struct'.\n");
				return 1;
			}
		}
		else
		if ( prefix_match(table, "group") )
		{
			int err;
			if ( prefix_match(reqs, "ints") )
			{
				struct nfsutil_group_ints  grp_ints;
				if ( to_uint_arg(key, &id) )
				{
					gid_t  gid = id;
					grp_ints = nfsutil_getgrgid_ints(gid);
					err = grp_ints.err;
					if ( err )
						nfsidmap_print_pwgrp_error(err, "pwgrp_test group ints", "group with ID", key, "", "", "");
				}
				else
				{
					grp_ints = nfsutil_getgrnam_ints(key);
					err = grp_ints.err;
					if ( err )
						nfsidmap_print_pwgrp_error(err, "pwgrp_test group ints", "group name", key, "", "", "");
				}

				if ( !err )
					print_group_ints(grp_ints, key);
			}
			else
			if ( prefix_match(reqs, "struct") )
			{
				struct group *grp;
				if ( to_uint_arg(key, &id) )
				{
					gid_t  gid = id;
					err = nfsutil_getgrgid_struct(&grp, gid);
					if ( err )
						nfsidmap_print_pwgrp_error(err, "pwgrp_test group struct", "group with ID", key, "", "", "");
				}
				else
				{
					err = nfsutil_getgrnam_struct(&grp, key);
					if ( err )
						nfsidmap_print_pwgrp_error(err, "pwgrp_test group struct", "group name", key, "", "", "");
				}

				if ( !err )
					print_group(grp, key);
			}
			else
			{
				printf("ERROR: 2nd argument must be either 'ints' or 'struct'.\n");
				return 1;
			}
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
		printf("    pwgrp_test  [login_name]\n");
		printf("    pwgrp_test  [passwd|group]  [name|uid|gid]\n");
		printf("    pwgrp_test  [passwd|group]  [ints|struct]  [name|uid|gid]\n");
		printf("\n");
		return 1;
	}
	return 0;
}
