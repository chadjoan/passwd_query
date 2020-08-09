/*
 *  passwd_query.h
 *
 *  Types and functions that improve upon standard passwd and group
 *  retrieval functions such as getpwnam_r and getgrnam_r.
 *
 *  Copyright (c) 2020 Chad Joan <chadjoan@gmail.com>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PASSWD_QUERY_H
#define PASSWD_QUERY_H

#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// The STACKMEM_SIZE_HINT definitions should be large enough to store
// the `buf_query_realloc_loop` object (privately declared in the .c file),
// any passwd/group struct, and also have some reasonable amount of space
// left over (~1024 bytes) to give to the `getpw***_r` and `getgr***_r`
// functions for scratch space and string returns.

/// The recommended number of bytes to stack-allocate and provide to
/// `nfsutil_pw_query_init` when using its `optional_stack_memory` and
/// `stack_memory_size` parameters.
#define PASSWD_STACKMEM_SIZE_HINT (1024)


/// The recommended number of bytes to stack-allocate and provide to
/// `nfsutil_grp_query_init` when using its `optional_stack_memory` and
/// `stack_memory_size` parameters.
#define GROUP_STACKMEM_SIZE_HINT  (1024)

/// This object stores return values and memory management state used
/// by the functions in this module that wrap the `getpwnam_r` and
/// `getpwuid_r` functions.
struct nfsutil_passwd_query { void  *internals; };

/// This object stores return values and memory management state used
/// by the functions in this module that wrap the `getgrnam_r` and
/// `getgrgid_r` functions.
struct nfsutil_group_query { void  *internals; };


/// The `nfsutil_pw_query_init` function prepares a `struct nfsutil_passwd_query`
/// variable for use and ensures that it has predictable contents.
///
/// This function must be called before any other `nfsutil_pw_query_*` functions
/// are called on the given `struct nfsutil_passwd_query`.
///
/// The `optional_stack_memory` and `stack_memory_size` parameters allow
/// the caller to provide stack-allocated memory for the query to use.
/// This should allow the query to avoid using `malloc` in most cases,
/// though this is not a guarantee, because the `passwd` table (file) may
/// have long entries that force a dynamic allocation, or the underlying
/// libc implementation may call arbitrary memory allocation routines such
/// as `malloc` and `realloc`.
///
/// To opt-out of using the `optional_stack_memory` and `stack_memory_size`
/// parameters, pass the arguments `NULL` and `0`, respectively. This will
/// cause subsequent `nfsutil_pw_query_*` functions to lazily allocate memory
/// using `malloc` or `realloc`.
///
/// Usage example:
///
/// static const char *null_alt(const char *str, const char *alt)
/// {
///     if ( str != NULL )
///         return str;
///     else
///         return alt;
/// }
///
/// static void example_print_passwd(const char *login_name)
/// {
///     char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
///     size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
///     struct  nfsutil_passwd_query  passwd_query;
///     int     err = -1;
///
///     nfsutil_pw_query_init(&passwd_query, bufptr, buflen);
///
///     while ( err != 0 )
///     {
///         err = nfsutil_pw_query_call_getpwnam_r(&passwd_query, login_name);
///         if ( err == EINTR )
///             continue;
///         else
///         if ( err == ENOMEM ) {
///             printf("Out of memory error while attempting to retrieve passwd entry for user %s\n",
///                 login_name);
///             nfsutil_pw_query_cleanup(&passwd_query);
///             return;
///         }
///         else
///         if ( err == EIO ) {
///             printf("I/O error during getpwnam_r: %s\n", strerror(err));
///             nfsutil_pw_query_cleanup(&passwd_query);
///             return;
///         }
///         else
///         //... etc ...
///         if ( err != 0 )
///         {
///             printf("Unhandled error from getpwnam_r: %s\n", strerror(err));
///             nfsutil_pw_query_cleanup(&passwd_query);
///             return;
///         }
///     }
///
///     struct passwd  *pw;
///     pw = nfsutil_pw_query_result(&passwd_query);
///     if ( pw == NULL )
///         printf("passwd entry not found for user '%s'\n", login_name);
///     else
///     {
///         // ... do things with `pw` ...
///         printf("passwd entry for '%s':\n", login_name);
///         printf("  name:  %s\n", null_alt(pw->pw_name, "<NULL>"));
///         printf("  uid:   %d\n", pw->pw_uid);
///         printf("  gid:   %d\n", pw->pw_gid);
///         printf("  dir:   %s\n", null_alt(pw->pw_dir, "<NULL>"));
///         printf("  shell: %s\n", null_alt(pw->pw_shell, "<NULL>"));
///     }
///
///     nfsutil_pw_query_cleanup(&passwd_query);
///     // Everything should be done by this point; `pw` is now invalid.
///
///     return;
/// }
///
void  nfsutil_pw_query_init(
	struct nfsutil_passwd_query  *query,
	void    *optional_stack_memory,
	size_t  stack_memory_size
	);


/// The `nfsutil_grp_query_init` function prepares a `struct nfsutil_group_query`
/// variable for use and ensures that it has predictable contents.
///
/// This function must be called before any other `nfsutil_grp_query_*` functions
/// are called on the given `struct nfsutil_group_query`.
///
/// The `optional_stack_memory` and `stack_memory_size` parameters allow
/// the caller to provide stack-allocated memory for the query to use.
/// This should allow the query to avoid using `malloc` in most cases,
/// though this is not a guarantee, because the `group` table (file) may
/// have long entries that force a dynamic allocation, or the underlying
/// libc implementation may call arbitrary memory allocation routines such
/// as `malloc` and `realloc`.
///
/// To opt-out of using the `optional_stack_memory` and `stack_memory_size`
/// parameters, pass the arguments `NULL` and `0`, respectively. This will
/// cause subsequent `nfsutil_grp_query_*` functions to lazily allocate memory
/// using `malloc` or `realloc`.
///
/// Usage example:
///
/// static const char *null_alt(const char *str, const char *alt)
/// {
///     if ( str != NULL )
///         return str;
///     else
///         return alt;
/// }
///
/// static void example_print_group(const char *group_name)
/// {
///     char    bufptr[GROUP_STACKMEM_SIZE_HINT];
///     size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
///     struct  nfsutil_group_query  group_query;
///     int     err = -1;
///
///     nfsutil_grp_query_init(&group_query, bufptr, buflen);
///
///     while ( err != 0 )
///     {
///         err = nfsutil_grp_query_call_getgrnam_r(&group_query, group_name);
///         if ( err == EINTR )
///             continue;
///         else
///         if ( err == ENOMEM ) {
///             printf("Out of memory error while attempting to retrieve group entry for group %s\n",
///                 group_name);
///             nfsutil_grp_query_cleanup(&group_query);
///             return;
///         }
///         else
///         if ( err == EIO ) {
///             printf("I/O error during getpwnam_r: %s\n", strerror(err));
///             nfsutil_grp_query_cleanup(&group_query);
///             return;
///         }
///         else
///         //... etc ...
///         if ( err != 0 )
///         {
///             printf("Unhandled error from getpwnam_r: %s\n", strerror(err));
///             nfsutil_grp_query_cleanup(&group_query);
///             return;
///         }
///     }
///
///     struct group  *grp;
///     grp = nfsutil_grp_query_result(&group_query);
///     if ( grp == NULL )
///         printf("group entry not found for group '%s'\n", group_name);
///     else
///     {
///         // ... do things with `grp` ...
///         printf("group entry for '%s':\n", group_name);
///         printf("  name:     %s\n", null_alt(grp->gr_name, "<NULL>"));
///         printf("  gid:      %d\n", grp->gr_gid);
///         char **members = grp->gr_mem;
///         for ( ssize_t i = 0; members[i] != NULL; i++ )
///         {
///             const char *member = members[i];
///             printf("  member[%ld]: %s\n", i, null_alt(member, "<NULL>"));
///         }
///     }
///
///     nfsutil_grp_query_cleanup(&group_query);
///     // Everything should be done by this point; `grp` is now invalid.
///
///     return;
/// }
///
void  nfsutil_grp_query_init(
	struct nfsutil_group_query  *query,
	void    *optional_stack_memory,
	size_t  stack_memory_size
	);


/// Searches the system's `passwd` file/database for the entry corresponding
/// to the given `login_name`.
///
/// This function (along with the `nfsutil_passwd_query` object) handles
/// all of the memory allocation needs of `getpwnam_r`, including reallocation
/// if initial buffer sizes are not sufficient.
///
/// Return values are the same as for `getpwnam_r`, with the addition of
/// `ENOMEM`, which is returned if memory (re)allocation (by `realloc`) fails.
///
/// See `nfsutil_pw_query_init` for a usage example.
///
/// For more details, see the `getpwnam_r` documentation:
/// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpwnam.html
///
int nfsutil_pw_query_call_getpwnam_r(
		struct nfsutil_passwd_query  *query,
		const char  *login_name
	);


/// Searches the system's `passwd` file/database for the entry corresponding
/// to the given `uid`.
///
/// This function (along with the `nfsutil_passwd_query` object) handles
/// all of the memory allocation needs of `getpwuid_r`, including reallocation
/// if initial buffer sizes are not sufficient.
///
/// Return values are the same as for `getpwuid_r`, with the addition of
/// `ENOMEM`, which is returned if memory (re)allocation (by `realloc`) fails.
///
/// See `nfsutil_pw_query_init` for a usage example.
///
/// For more details, see the `getpwuid_r` documentation:
/// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpwuid.html
///
int nfsutil_pw_query_call_getpwuid_r(
		struct nfsutil_passwd_query  *query,
		uid_t   uid
	);


/// Searches the system's `group` file/database for the entry corresponding
/// to the given `group_name`.
///
/// This function (along with the `nfsutil_group_query` object) handles
/// all of the memory allocation needs of `getgrnam_r`, including reallocation
/// if initial buffer sizes are not sufficient.
///
/// Return values are the same as for `getgrnam_r`, with the addition of
/// `ENOMEM`, which is returned if memory (re)allocation (by `realloc`) fails.
///
/// See `nfsutil_grp_query_init` for a usage example.
///
/// For more details, see the `getgrnam_r` documentation:
/// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrnam.html
///
int nfsutil_grp_query_call_getgrnam_r(
		struct nfsutil_group_query  *query,
		const char  *group_name
	);


/// Searches the system's `group` file/database for the entry corresponding
/// to the given `gid`.
///
/// This function (along with the `nfsutil_group_query` object) handles
/// all of the memory allocation needs of `getgrgid_r`, including reallocation
/// if initial buffer sizes are not sufficient.
///
/// Return values are the same as for `getgrgid_r`, with the addition of
/// `ENOMEM`, which is returned if memory (re)allocation (by `realloc`) fails.
///
/// See `nfsutil_grp_query_init` for a usage example.
///
/// For more details, see the `getgrgid_r` documentation:
/// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid.html
///
int nfsutil_grp_query_call_getgrgid_r(
		struct nfsutil_group_query  *query,
		gid_t   gid
	);


/// These functions retrieve the `struct passwd` or `struct group` object
/// returned by earlier calls to `nfsutil_pw_query_call_*` or
/// `nfsutil_grp_query_call_*` functions.
///
/// These objects are only valid as long as the `nfsutil_passwd_query`
/// or `nfsutil_group_query` object is still "live". The memory used
/// for these might be released and/or wiped when `nfsutil_pw_query_cleanup`
/// or `nfsutil_grp_query_cleanup` are called. So if the caller needs to
/// persist these data past any calls to query cleanup functions, the caller
/// should perform a deep copy of these objects into longer-lasting memory
/// regions.
///
/// Returns: NULL if no querying function was previously called, NULL if
///   there was no entry found during the previous query, or a pointer
///   to a `struct passwd` or `struct group` object within the query's
///   memory buffer.
struct passwd *nfsutil_pw_query_result(struct nfsutil_passwd_query *query);

/// ditto
struct group *nfsutil_grp_query_result(struct nfsutil_group_query *query);


/// These functions release (and, if appropriate, sanitize) any resources
/// that were allocated by the query object passed into the `query` parameter.
///
/// These are safe to call even if the query used stack memory exclusively.
/// The query functions will never attempt to free stack memory, or any
/// other forms of caller-allocated memory, and will only free memory that
/// the query owns (e.g. from having called `malloc` or `realloc` internally).
///
/// To avoid potential memory leaks, these cleanup functions should always
/// be called after any work involving query objects has concluded.
///
void nfsutil_pw_query_cleanup(struct nfsutil_passwd_query *query);

/// ditto
void nfsutil_grp_query_cleanup(struct nfsutil_group_query *query);

#endif /* PASSWD_QUERY_H */
