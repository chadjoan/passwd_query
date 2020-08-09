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

// This integer constant describes how many bytes of memory should be
// (ideally) placed on the stack and passed into the `nfsutil_pw_query_init`
// function's `optional_stack_memory` and `stack_memory_size`
// parameters. This should allow the passwd query to avoid an
// unnecessary mallocation in most cases.
#ifndef PASSWD_QUERY_H
#define PASSWD_QUERY_H

#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

//#define PASSWD_STACKMEM_SIZE_HINT (512+64+1)
#define PASSWD_STACKMEM_SIZE_HINT (1024)
#define GROUP_STACKMEM_SIZE_HINT  (1024)

struct nfsutil_passwd_query { void  *internals; };
struct nfsutil_group_query { void  *internals; };

//
// Example usage:
//
// void my_func(const char *login_name)
// {
// #define OOM_MESSAGE ("Out of memory error while attempting to retrieve passwd entry for user %s\n")
//     char[PASSWD_STACKMEM_SIZE_HINT]  bufptr;
//     size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
//     struct  nfsutil_passwd_query  passwd_query;
//     int     err = -1;
//
//     nfsutil_pw_query_init(&passwd_query);
//
//     while ( err != 0 )
//     {
//         err = nfsutil_pw_query_call_getpwnam_r(&passwd_query, login_name);
//         if ( err == EINTR )
//             continue;
//         else
//         if ( err == ENOMEM ) {
//             printf(OOM_MESSAGE, login_name);
//             nfsutil_pw_query_cleanup(&passwd_query);
//             return;
//         }
//         else
//         if ( err == EIO ) {
//             printf("I/O error during getpwnam_r: %s\n", strerror(err));
//             nfsutil_pw_query_cleanup(&passwd_query);
//             return;
//         }
//         else
//         ... etc ...
//     }
//
//     struct passwd  *pw;
//     pw = nfsutil_pw_query_result(&passwd_query);
//     ... do things with `pw` ...
//
//     nfsutil_pw_query_cleanup(&passwd_query);
//     // Everything should be done by this point; `pw` is now invalid.
//
//     return;
// #undefine OOM_MESSAGE
// }
//
void  nfsutil_pw_query_init(
	struct nfsutil_passwd_query  *query,
	void    *optional_stack_memory,
	size_t  stack_memory_size
	);

void  nfsutil_grp_query_init(
	struct nfsutil_group_query  *query,
	void    *optional_stack_memory,
	size_t  stack_memory_size
	);

// Searches the system's `passwd` file/database for the entry corresponding
// to the given `login_name`.
//
// This function (along with the `nfsutil_passwd_query` object) handles
// all of the memory allocation needs of `getpwnam_r`, including reallocation
// if initial buffer sizes are not sufficient.
//
// Return values are the same as for `getpwnam_r`, with the addition of
// `ENOMEM`, which is returned if memory reallocation (by `realloc`) fails.
//
// See `nfsutil_pw_query_init` for a usage example.
//
// For more details, see the `getpwnam_r` documentation:
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpwnam.html
//
int nfsutil_pw_query_call_getpwnam_r(
	struct nfsutil_passwd_query  *query,
	const char  *login_name
	);

int nfsutil_pw_query_call_getpwuid_r(
		struct nfsutil_passwd_query  *query,
		uid_t   uid
	);

int nfsutil_grp_query_call_getgrnam_r(
		struct nfsutil_group_query  *query,
		const char  *group_name
	);

int nfsutil_grp_query_call_getgrgid_r(
		struct nfsutil_group_query  *query,
		gid_t   gid
	);

struct passwd *nfsutil_pw_query_result(struct nfsutil_passwd_query *query);
struct group *nfsutil_grp_query_result(struct nfsutil_group_query *query);

void nfsutil_pw_query_cleanup(struct nfsutil_passwd_query *query);
void nfsutil_grp_query_cleanup(struct nfsutil_group_query *query);

#endif /* PASSWD_QUERY_H */
