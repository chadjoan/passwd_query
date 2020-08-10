# passwd_query
Types and functions for querying user/group information without buffer overflow risks.

Opportunistic (and safe) stack allocation and minimal caller-side error handling are also provided.

This code was written as part of a patch to the `nfs-utils` codebase to fix [bug 344](https://bugzilla.linux-nfs.org/show_bug.cgi?id=344). I made a separate repository for this code to give the example/test program (`pwgrp_test.c`) a place to live (I'm not sure if it's appropriate to submit the example program to nfs-utils, given that it isn't an automated test and doesn't do anything nfs related). Unless this code finds other uses, it is mostly just a record of how I isolated the `passwd_query.(c|h)` module and verified that it works correctly. This module has no dependencies on other nfs-utils code, or anything else really, with the necessary exception of the handful of POSIX C functions that it specifically improves upon.

I'm not planning on doing anything else with this code for now, so it might stay in this pre-integration state indefinitely. There is currently no point for it to have its own build system, generated documentation, or other whole-project niceties. If anyone needs it, I *did* write a lot of comments and documented the functions within as well as I could within the time constraints of an "I thought this was going to be much simpler"-type small project. So the in-line documentation should be pretty comprehensive, but might still have a few typos, ambiguities, or poorly worded phrases.
