#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>  // For uid_t/gid_t

#include "passwd_query.h"

struct buffered_query
{
	// Number of bytes allocated to this nfsutil_passwd_query object.
	size_t   allocation_size;


	// This tracks whether or not the query object owns its own memory.
	// Since `malloc` is the current allocator, this determines whether or not
	// our memory needs to be given to the `free` function during cleanup.
	// 0 means no/false, 1 means yes/true.
	uint8_t  own_allocation;


	// Set to 0 if the query deduced that the given name/uid/whatever
	// does not exist in the system's table being queried (ex: passwd file).
	// Otherwise, it is set to 1 to indicate that the entry was found.
	// In the latter case, the query's buffer 
	// field will be populated with the contents of that row/entry.
	uint8_t  entry_exists;


	// Accessing this member returns a pointer to the memory allocated
	// beyond the `buffered_query` struct. This memory is used to store
	// buffer/return structs and provide query functions (ex: getpwnam_r,
	// getgrnam_r, and so on) with scratch space and a place to put
	// dynamically allocated results (ex: strings pointed to from
	// a struct being returned).
	//
	// The `buf_query_get_buffer_size` function returns the size
	// of this memory region.
	//
	// More specific query types should provide functions for partitioning
	// this memory space, ex: for returning statically-positioned structs
	// or returning the remaining untyped portion.
	char     buffer_start[];

	/*
	// This union allows the query object to store either passwd or group
	// information, depending on what the caller requested.
	//
	// This struct is modified by functions like `getpwnam_r`.
	// In all cases it is effectively the returned data.
	//
	union u
	{
		// The POSIX functions such as `getpwnam_r` and `getpwuid_r`
		// require both a structure (`passwd` or `group`) and a buffer
		// of memory in their parameter list. The structure is used to
		// store the results of the function call, and the buffer memory
		// holds any strings or other dynamic data that is pointed to
		// from within the aforementioned structures.
		//
		// There are simple structs within this union, and those are used
		// to pair each result struct with a flexible array that denotes
		// where its corresponding buffer memory begins.
		//
		// In other words, the buffer's beginning location will change
		// depending on which role (passwd vs group) the query object
		// is serving.

		struct s1 {
			struct passwd  pw;
			char           buffer[];
		}
		passwd;

		struct s2 {
			struct group   grp;
			char           buffer[];
		}
		group;

	}
	results;
	*/
};

// ----- generic buffered query memory partitioning -----

// This pointer-length pair is used to simplify the getter functions used to
// return memory regions from the various types of buffered queries.
struct buffer_region
{
	void    *ptr;
	size_t  len;
};

// Returns the number of bytes allocated past the query's `buffer_start` address.
static size_t buf_query_get_buffer_size(struct buffered_query *query)
{
	return query->allocation_size - ((char*)query->buffer_start - (char*)query);
}

// Returns the region of memory associated with the query's `buffer_start`
// member. This is a pointer-length pair with `buffer_start` being the pointer
// and the result of calling `buf_query_get_buffer_size` being the length.
static struct buffer_region
	buf_query_get_buffer(struct buffered_query *query)
{
	struct buffer_region  buf;
	buf.ptr = query->buffer_start;
	buf.len = buf_query_get_buffer_size(query);
	return buf;
}

// ----- passwd query memory partitioning -----

// Returns a pointer to the region of the query's memory that contains the
// `passwd` struct. This struct is modified by the `getpwnam_r` and
// `getpwuid_r` functions, and is effectively part of their return value.
//
// The rest of the data returned by `getpwnam_r` and `getpwuid_r` is stored in
// the rest of the query object's memory buffer, which is accessible through
// the `passwd_query_get_bufptr` and `passwd_query_get_buflen` functions.
static struct passwd *passwd_query_get_passwd(struct buffered_query *query)
{
	return (struct passwd*)query->buffer_start;
}

// Returns a the region of the query's memory that is not occupied by the
// `passwd` struct. This region is used by functions like `getpwnam_r`
// and `getpwuid_r` to store dynamic data related to the struct they return,
// such as string data that is referenced by the `passwd` struct.
static struct buffer_region
	passwd_query_get_buffer(struct buffered_query *query)
{
	struct buffer_region  buf = buf_query_get_buffer(query);
	buf.ptr += sizeof(struct passwd);
	buf.len -= sizeof(struct passwd);
	return buf;
}

// ----- group query memory partitioning -----
/*
TODO: documentation
*/

static struct group *group_query_get_group(struct buffered_query *query)
{
	return (struct group*)query->buffer_start;
}

static struct buffer_region
	group_query_get_buffer(struct buffered_query *query)
{
	struct buffer_region  buf = buf_query_get_buffer(query);
	buf.ptr += sizeof(struct group);
	buf.len -= sizeof(struct group);
	return buf;
}


#define PWQ_INSTANCE_SIZE   (sizeof(struct buffered_query) + sizeof(struct passwd))
#define PWQ_RESULTS_BUFFER_SIZE_MIN   (512)
#define PWQ_MEMORY_DEMAND   (PWQ_INSTANCE_SIZE + PWQ_RESULTS_BUFFER_SIZE_MIN)
#define GRPQ_INSTANCE_SIZE  (sizeof(struct buffered_query) + sizeof(struct group))
#define GRPQ_RESULTS_BUFFER_SIZE_MIN  (512)
#define GRPQ_MEMORY_DEMAND  (GRPQ_INSTANCE_SIZE + GRPQ_RESULTS_BUFFER_SIZE_MIN)

/*
struct group_query_private
{
	size_t         allocation_size;
	char           *bufptr;
	size_t         buflen;
	struct group   group_buffer;
	uint8_t        buffer_needs_freeing;
	int            return_code;
	
};
*/

/*
static size_t pw_query_results_buffer_size(struct buffered_query *query)
{
	return (query->allocation_size) - sizeof(struct buffered_query);
}
*/

static void buf_query_populate(
	struct buffered_query *query,
	size_t   alloc_size,
	uint8_t  own_allocation
	)
{
	// Gently encourage determinism.
	memset(query, 0, alloc_size);

	// Fill data in.
	query->allocation_size = alloc_size;
	query->own_allocation = own_allocation;
}

// Returns 0 upon success, or ENOMEM to indicate an out-of-memory condition.
static int buf_query_mallocate_if_needed(struct buffered_query **query, size_t memory_demand_guess)
{
	// Non-NULL indicates that nfsutil_pw_query_init already found memory for it.
	if ( *query != NULL )
		return 0;

	// *query == NULL
	// Which means that mallocation is needed.
	*query = malloc(memory_demand_guess);
	if ( *query == NULL )
		return ENOMEM;

	size_t own_allocation = 1;
	buf_query_populate(*query, memory_demand_guess, own_allocation);
	return 0;
}

/*
static pw_query_zero(struct buffered_query *query)
{
	size_t resbufsz = pw_query_results_buffer_size(query);
	query->return_code = 0;
	memset(&query->passwd_buffer, 0, sizeof(query->passwd_buffer));
	memset(&query->results_buffer, 0, sizeof(query->results_buffer));
}
*/

static void buf_query_init(
		struct buffered_query  **query,
		void    *optional_stack_memory,
		size_t  stack_memory_size,
		size_t  memory_demand_guess
	)
{
	// Use stack memory if available, otherwise malloc.
	if ( optional_stack_memory && (stack_memory_size > memory_demand_guess) )
	{
		*query = optional_stack_memory;
		size_t own_allocation = 0;
		buf_query_populate(*query, stack_memory_size, own_allocation);
	}
	else
	{
		// Delay mallocation until it's needed.
		// That way, we don't need to return error codes from this
		// function, which makes the caller's side much cleaner.
		// (In other words, the caller only needs to handle ENOMEM
		// in (probably) one place.)
		// This is done my ensuring that query->internals is a
		// predictable value; NULL in this case.
		*query = NULL;
	}
}

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
	)
{
	buf_query_init(
		(struct buffered_query **)&query->internals,
		optional_stack_memory,
		stack_memory_size,
		PWQ_MEMORY_DEMAND);
}

void  nfsutil_grp_query_init(
	struct nfsutil_group_query  *query,
	void    *optional_stack_memory,
	size_t  stack_memory_size
	)
{
	buf_query_init(
		(struct buffered_query **)&query->internals,
		optional_stack_memory,
		stack_memory_size,
		GRPQ_MEMORY_DEMAND);
}


// ----- Various query runner functions. -----
union pwgrp_key
{
	const char *as_name;
	uid_t      as_uid;
	gid_t      as_gid;
};

// This logic was factored out of the query runners to avoid code duplication.
// It uses the outputs of the various system querying functions (ex: getpwnam_r)
// to determine if we need to allocate more memory, and if not, to update the
// state of our query object based on the results of the call.
static void pwgrp_reflect_outcome(

		// Things to analyze
		int    return_code,
		void   *entry_exists,

		// Things to update
		ssize_t *memory_shortage,
		struct buffered_query *query,
		void   *result,
		size_t result_sizeof
	)
{
	if ( return_code == ERANGE )
	{
		*memory_shortage = -1;

		// Clear all buffer memory so the results of this aborted call
		// can't (negatively) affect the results of future attempts.
		struct buffer_region buf = buf_query_get_buffer(query);
		memset(buf.ptr, 0, buf.len);
	}
	else
	{
		*memory_shortage = 0;

		if ( entry_exists )
			query->entry_exists = 1;
		else
		{
			query->entry_exists = 0;

			// Clear the returned struct so that any code that ignores
			// the (entry_exists == 0) status will at least get
			// data that obviously looks blank, instead of getting
			// whatever undefined contents the system function
			// (ex: getpwnam_r, getgrnam_r) left there.
			// Basically, this should make bugs easier to spot and reproduce.
			memset(result, 0, result_sizeof);
		}
	}
}

static int call_getpwnam_r(
		void *caller_context,
		struct buffered_query *query,
		ssize_t *memory_shortage
	)
{
	union pwgrp_key  *key          = caller_context;
	const char       *login_name   = key->as_name;
	struct passwd    *result       = passwd_query_get_passwd(query);
	struct passwd    *entry_exists = NULL;

	struct buffer_region buf = passwd_query_get_buffer(query);

	// Attempt to look up the desired passwd entry by login name.
	int return_code = getpwnam_r(
			login_name, result,
			buf.ptr, buf.len,
			&entry_exists);

	// Update *memory_shortage and query state.
	pwgrp_reflect_outcome(
		return_code, entry_exists,
		memory_shortage, query, result, sizeof(*result));

	return return_code;
}

static int call_getpwuid_r(
		void *caller_context,
		struct buffered_query *query,
		ssize_t *memory_shortage
	)
{
	union pwgrp_key  *key          = caller_context;
	uid_t            uid           = key->as_uid;
	struct passwd    *result       = passwd_query_get_passwd(query);
	struct passwd    *entry_exists = NULL;

	struct buffer_region buf = passwd_query_get_buffer(query);

	// Attempt to look up the desired passwd entry by login name.
	int return_code = getpwuid_r(
			uid, result,
			buf.ptr, buf.len,
			&entry_exists);

	// Update *memory_shortage and query state.
	pwgrp_reflect_outcome(
		return_code, entry_exists,
		memory_shortage, query, result, sizeof(*result));

	return return_code;
}

static int call_getgrnam_r(
		void *caller_context,
		struct buffered_query *query,
		ssize_t *memory_shortage
	)
{
	union pwgrp_key  *key          = caller_context;
	const char       *group_name   = key->as_name;
	struct group     *result       = group_query_get_group(query);
	struct group     *entry_exists = NULL;

	struct buffer_region buf = group_query_get_buffer(query);

	// Attempt to look up the desired group entry by login name.
	int return_code = getgrnam_r(
			group_name, result,
			buf.ptr, buf.len,
			&entry_exists);

	// Update *memory_shortage and query state.
	pwgrp_reflect_outcome(
		return_code, entry_exists,
		memory_shortage, query, result, sizeof(*result));

	return return_code;
}

static int call_getgrgid_r(
		void *caller_context,
		struct buffered_query *query,
		ssize_t *memory_shortage
	)
{
	union pwgrp_key  *key          = caller_context;
	gid_t            gid           = key->as_gid;
	struct group     *result       = group_query_get_group(query);
	struct group     *entry_exists = NULL;

	struct buffer_region buf = group_query_get_buffer(query);

	// Attempt to look up the desired group entry by login name.
	int return_code = getgrgid_r(
			gid, result,
			buf.ptr, buf.len,
			&entry_exists);

	// Update *memory_shortage and query state.
	pwgrp_reflect_outcome(
		return_code, entry_exists,
		memory_shortage, query, result, sizeof(*result));

	return return_code;
}

// ----- realloc loop functions -----
// Any pointers to things like query->internal will need to be updated after
// calling this, as the value of query->internal may change.
//
// Returns 0 if successful, otherwise ENOMEM to indicate an out-of-memory condition.
//
static int buf_query_realloc_upsize(struct buffered_query **query)
{
	size_t oldsize = (*query)->allocation_size;
	size_t newsize = oldsize * 2;
	void *oldptr = *query;
	void *newptr = NULL;

	if ( !(*query)->own_allocation )
	{
		// Memory was not allocated by us. It might be stack memory or something.
		// Passing this memory to `realloc` might incur the wrath of the
		// Undefined Behavior gods, so let's not do that.
		// Instead, we'll `malloc` some new memory and copy our stuff over to that.
		newptr = malloc(newsize);
		if ( newptr == NULL )
			return ENOMEM;

		memcpy(newptr, oldptr, oldsize);
	}
	else
	{
		// Memory was already allocated with `malloc`, so we can pass the
		// pointer to `realloc` without incurring the wrath of the
		// Undefined Behavior gods.
		newptr = realloc(oldptr, newsize);
		if ( newptr == NULL )
			return ENOMEM;
	}

	// Update pointers and metadata to reflect what just happened.
	*query = newptr;
	(*query)->allocation_size = newsize;
	(*query)->own_allocation = 1;
	memset(newptr + oldsize, 0, newsize - oldsize);

	return 0;
}

/*
TODO: update docs!
*/


// This function implements a reallocation loop in a reusable manner.
// It will call a caller-supplied function, named as the `query_runner`
// parameter, and if that function requires more memory, it will call
// it over again repeatedly while increasing the size of provided memory
// until `query_runner` can complete without exhausting memory.
//
// `bufptr` and `buflen` are pointers to a caller-supplied
// initial memory buffer, which is usually going to be sized according to
// some best-effort guess at what will cover the vast majority of cases,
// and is usually going to be allocated from part of the stack.
// `realloc_loop` will update the values pointed to by these as reallocation
// happens. The caller may need this information to update its own pointers
// or size measurements if the initial buffer was moved.
//
// The `query_runner` function pointer shall point to a function that calls
// whatever function needs a memory buffer allocated for it.
// The `caller_context` allows the caller to pass data into the
// `query_runner` function, such as any non-buffer arguments to the
// underlying system function.
//
// `query_runner` may be called multiple times if the provided buffer (described
// by the `bufptr` and `buflen` pair) was not large enough for `query_runner`
// to complete its task. The `query_runner` function shall set the value pointed
// to by the `memory_shortage` argument to -1 if it failed due to
// an insufficiently large buffer, or to 0 if the buffer was large enough
// to complete the call. Positive values of `*memory_shortage` can be used
// to indicate how much memory is needed, though this is currently not implemented.
//
// The integer returned from `query_runner` shall be whatever return code the
// underlying function returned, including unhandled error codes.
// The `realloc_loop` function will then return that integer value to the caller.
//
// Thus, `realloc_loop` returns whatever `query_runner` returns after
// `query_runner` has been provided with enough memory (through `bufptr`
// and `buflen`) to finish executing completely (whether successful or not).
// `realloc_loop` may additionally return ENOMEM if an out-of-memory condition
// was encountered while attempting to enlarge the buffer it send to the
// `query_runner` function.
//
static int buf_query_realloc_loop(
		void    *caller_context,
		struct  buffered_query **query,
		size_t  memory_demand_guess,
		int (*query_runner)(
			void *caller_context,
			struct buffered_query *query,
			ssize_t *memory_shortage
		)
	)
{
	// query's internals may or may not be allocated at this point.
	// We ensure that it is.
	int oom = buf_query_mallocate_if_needed(query, memory_demand_guess);
	if ( oom )
		return oom;

	ssize_t memory_shortage = 0;
	while (1)
	{
		// Attempt to perform the action that requires variable memory.
		int return_code = query_runner(
				caller_context, *query, &memory_shortage);

		if ( memory_shortage != 0 ) {
			// Our buffer was not large enough. Upsize.
			oom = buf_query_realloc_upsize(query);
			if ( oom )
				return oom;
			continue;
		}
		else
		if ( return_code != 0 ) {
			// Other errors: it's the caller's responsibility.
			return return_code;
		}
		else {
			// Success!
			break;
		}
	}
	
}

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
	)
{
	// Notably, we don't use "sysconf(_SC_GETPW_R_SIZE_MAX)" anywhere in this
	// function. That's because it is likely to return either
	// -1 (which isn't helpful, but is at least honest) or
	// some wild guess (which is misleading and requires us to realloc-loop ANYWAYS).
	// As of this writing (2020-08-07), musl libc does the former.
	// Supposedly, glibc does the latter.
	// The real-life implications are what caused this bug report:
	// https://bugzilla.linux-nfs.org/show_bug.cgi?id=344
	//
	// This all means that the optimal strat involves completely ignoring
	// sysconf and instead directly proceeding to use a realloc-loop,
	// because we would need to do that regardless.
	//
	// Now then, onwards!
/*
	// getpwnam_r likes to return this pointer. It is just about
	// redundant with the other arguments in every way except for one:
	// it can be used to indicate the lookup was a "success" but there
	// were no entries matching the given request.
	// Otherwise, it's just going to point to the passwd struct we give it,
	// and it otherwise indicates errors, but return_code also does that.
	struct passwd *result;

	// This holds getpwnam_r's return code (or error code).
	int  return_code;
	
	call the thing(sdljkafsdjk)
*/
	union pwgrp_key  key;
	key.as_name = login_name;

	return buf_query_realloc_loop(&key,
		(struct buffered_query **)&query->internals,
		PWQ_MEMORY_DEMAND, &call_getpwnam_r);
/*
	if ( result == NULL ) {
		query_->entry_exists = 0;
		memset(&query_->passwd_buffer, 0, sizeof(query_->passwd_buffer));
	}
	else
		query_->entry_exists = 1;

	return return_code;
*/
}

int nfsutil_pw_query_call_getpwuid_r(
		struct nfsutil_passwd_query  *query,
		uid_t   uid
	)
{
	union pwgrp_key  key;
	key.as_uid = uid;

	return buf_query_realloc_loop(&key,
		(struct buffered_query **)&query->internals,
		PWQ_MEMORY_DEMAND, &call_getpwuid_r);
}

int nfsutil_grp_query_call_getgrnam_r(
		struct nfsutil_group_query  *query,
		const char  *group_name
	)
{
	union pwgrp_key  key;
	key.as_name = group_name;

	return buf_query_realloc_loop(&key,
		(struct buffered_query **)&query->internals,
		GRPQ_MEMORY_DEMAND, &call_getgrnam_r);
}

int nfsutil_grp_query_call_getgrgid_r(
		struct nfsutil_group_query  *query,
		gid_t   gid
	)
{
	union pwgrp_key  key;
	key.as_gid = gid;

	return buf_query_realloc_loop(&key,
		(struct buffered_query **)&query->internals,
		GRPQ_MEMORY_DEMAND, &call_getgrgid_r);
}

struct passwd *nfsutil_pw_query_result(struct nfsutil_passwd_query *query)
{
	if ( query->internals == NULL )
		return NULL;
	else
	{
		struct buffered_query *query_ = query->internals;
		if ( query_->entry_exists )
			return passwd_query_get_passwd(query_);
		else
			return NULL;
	}
}

struct group *nfsutil_grp_query_result(struct nfsutil_group_query *query)
{
	if ( query->internals == NULL )
		return NULL;
	else
	{
		struct buffered_query *query_ = query->internals;
		if ( query_->entry_exists )
			return group_query_get_group(query_);
		else
			return NULL;
	}
}

static void buf_query_cleanup(struct buffered_query **query)
{
	if ( *query == NULL )
		return;

	uint8_t  do_free = (*query)->own_allocation;

	// Zero out the memory we used, for at least these reasons:
	// * It makes dangling-pointer bugs easier to find.
	// * It mitigates unforeseen security consequences by
	//     refusing to leave login/group names laying around in memory.
	memset(*query, 0, (*query)->allocation_size);

	// `free` as needed.
	if ( do_free )
		free(*query);

	// Leave the `nfsutil_passwd_query` or `nfsutil_group_query`
	// in a predictable state.
	*query = NULL;
}

void nfsutil_pw_query_cleanup(struct nfsutil_passwd_query *query)
{
	buf_query_cleanup((struct buffered_query **)&query->internals);
}

void nfsutil_grp_query_cleanup(struct nfsutil_group_query *query)
{
	buf_query_cleanup((struct buffered_query **)&query->internals);
}
