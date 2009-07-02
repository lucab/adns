/*
 * adns.h
 * - adns user-visible API (single-threaded, without any locking)
 */
/*
 *  This file is part of adns, which is Copyright (C) 1997-1999 Ian Jackson
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  $Id: adns.h,v 1.55 1999/08/05 00:03:24 ian Exp $
 */

#ifndef ADNS_H_INCLUDED
#define ADNS_H_INCLUDED
#ifdef __cplusplus
extern "C" { /* I really dislike this - iwj. */
#endif

#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

/* All struct in_addr anywhere in adns are in NETWORK byte order. */

typedef struct adns__state *adns_state;
typedef struct adns__query *adns_query;

typedef enum {
  adns_if_noenv=        0x0001, /* do not look at environment */
  adns_if_noerrprint=   0x0002, /* never print output to stderr (_debug overrides) */
  adns_if_noserverwarn= 0x0004, /* do not warn to stderr about duff nameservers etc */
  adns_if_debug=        0x0008, /* enable all output to stderr plus debug msgs */
  adns_if_noautosys=    0x0010, /* do not make syscalls at every opportunity */
  adns_if_eintr=        0x0020, /* allow _wait and _synchronous to return EINTR */
  adns_if_nosigpipe=    0x0040, /* applic has SIGPIPE set to SIG_IGN, do not protect */
} adns_initflags;

typedef enum {
  adns_qf_search=          0x000001, /* use the searchlist */
  adns_qf_usevc=           0x000002, /* use a virtual circuit (TCP connection) */
  adns_qf_owner=           0x000004, /* fill in the owner field in the answer */
  adns_qf_quoteok_query=   0x000010, /* allow quote-requiring chars in query domain */
  adns_qf_quoteok_cname=   0x000020, /* allow ... in CNAME we go via */
  adns_qf_quoteok_anshost= 0x000040, /* allow ... in answers expected to be hostnames */
  adns_qf_cname_loose=     0x000100, /* allow refs to CNAMEs - without, get _s_cname */
  adns_qf_cname_forbid=    0x000200, /* don't follow CNAMEs, instead give _s_cname */
  adns__qf_internalmask=   0x0ff000
} adns_queryflags;

typedef enum {
  adns__rrt_typemask=  0x0ffff,
  adns__qtf_deref=     0x10000, /* dereference domains and perhaps produce extra data */
  adns__qtf_mail822=   0x20000, /* make mailboxes be in RFC822 rcpt field format */
  
  adns_r_none=               0,
  
  adns_r_a=                  1,
  
  adns_r_ns_raw=             2,
  adns_r_ns=                    adns_r_ns_raw|adns__qtf_deref,
  
  adns_r_cname=              5,
  
  adns_r_soa_raw=            6,
  adns_r_soa=                   adns_r_soa_raw|adns__qtf_mail822, 
  
  adns_r_ptr_raw=           12,
  adns_r_ptr=                   adns_r_ptr_raw|adns__qtf_deref,
  
  adns_r_hinfo=             13,  
  
  adns_r_mx_raw=            15,
  adns_r_mx=                    adns_r_mx_raw|adns__qtf_deref,
  
  adns_r_txt=               16,
  
  adns_r_rp_raw=            17,
  adns_r_rp=                    adns_r_rp_raw|adns__qtf_mail822,

  adns_r_addr=                  adns_r_a|adns__qtf_deref
  
} adns_rrtype;

/* In queries without qf_quoteok_*, all domains must have standard
 * legal syntax.  In queries _with_ qf_quoteok_*, domains in the query
 * or response may contain any characters, quoted according to RFC1035
 * 5.1.  On input to adns, the char* is a pointer to the interior of a
 * " delimited string, except that " may appear in it, and on output,
 * the char* is a pointer to a string which would be legal either
 * inside or outside " delimiters, and any characters not usually
 * legal in domain names will be quoted as \X (if the character is
 * 33-126 except \ and ") or \DDD.
 *
 * Do not ask for _raw records containing mailboxes without
 * specifying _qf_anyquote.
 */

typedef enum {
  adns_s_ok,

  /* locally induced errors */
  adns_s_nomemory,
  adns_s_unknownrrtype,
  adns_s_systemfail,

  adns_s_max_localfail= 29,
  
  /* remotely induced errors, detected locally */
  adns_s_timeout,
  adns_s_allservfail,
  adns_s_norecurse,
  adns_s_invalidresponse,
  adns_s_unknownformat,

  adns_s_max_remotefail= 59,
  
  /* remotely induced errors, reported by remote server to us */
  adns_s_rcodeservfail,
  adns_s_rcodeformaterror,
  adns_s_rcodenotimplemented,
  adns_s_rcoderefused,
  adns_s_rcodeunknown,

  adns_s_max_tempfail= 99,

  /* remote configuration errors */
  adns_s_inconsistent, /* PTR gives domain whose A does not exist and match */
  adns_s_prohibitedcname, /* CNAME found where eg A expected (not if _qf_loosecname) */
  adns_s_answerdomaininvalid,
  adns_s_answerdomaintoolong,
  adns_s_invaliddata,
  
  adns_s_max_misconfig= 199,

  /* permanent problems with the query */
  adns_s_querydomainwrong,
  adns_s_querydomaininvalid,
  adns_s_querydomaintoolong,
  
  adns_s_max_misquery= 299,

  /* permanent errors */
  adns_s_nxdomain,
  adns_s_nodata,
  
} adns_status;

typedef struct {
  int len;
  union {
    struct sockaddr sa;
    struct sockaddr_in inet;
  } addr;
} adns_rr_addr;

typedef struct {
  char *host;
  adns_status astatus;
  int naddrs; /* temp fail => -1, perm fail => 0, s_ok => >0 */
  adns_rr_addr *addrs;
} adns_rr_hostaddr;

typedef struct {
  char *(array[2]);
} adns_rr_strpair;

typedef struct {
  int i;
  adns_rr_hostaddr ha;
} adns_rr_inthostaddr;

typedef struct {
  /* Used both for mx_raw, in which case i is the preference and str the domain,
   * and for txt, in which case each entry has i for the `text' length,
   * and str for the data (which will have had an extra nul appended
   * so that if it was plain text it is now a null-terminated string).
   */
  int i;
  char *str;
} adns_rr_intstr;

typedef struct {
  adns_rr_intstr array[2];
} adns_rr_intstrpair;

typedef struct {
  char *mname, *rname;
  unsigned long serial, refresh, retry, expire, minimum;
} adns_rr_soa;

typedef struct {
  adns_status status;
  char *cname; /* always NULL if query was for CNAME records */
  char *owner; /* only set if requested in query flags */
  adns_rrtype type; /* guaranteed to be same as in query */
  time_t expires; /* expiry time, defined only if _s_ok, nxdomain or nodata. NOT TTL! */
  int nrrs, rrsz;
  union {
    void *untyped;
    unsigned char *bytes;
    char *(*str);                     /* ns_raw, cname, ptr, ptr_raw */
    adns_rr_intstr *(*manyistr);      /* txt (list of strings ends with i=-1, str=0) */
    adns_rr_addr *addr;               /* addr */
    struct in_addr *inaddr;           /* a */
    adns_rr_hostaddr *hostaddr;       /* ns */
    adns_rr_intstrpair *intstrpair;   /* hinfo */
    adns_rr_strpair *strpair;         /* rp, rp_raw */
    adns_rr_inthostaddr *inthostaddr; /* mx */
    adns_rr_intstr *intstr;           /* mx_raw */
    adns_rr_soa *soa;                 /* soa, soa_raw */
  } rrs;
} adns_answer;

/* Memory management:
 *  adns_state and adns_query are actually pointers to malloc'd state;
 *  On submission questions are copied, including the owner domain;
 *  Answers are malloc'd as a single piece of memory; pointers in the
 *  answer struct point into further memory in the answer.
 * query_io:
 *  Must always be non-null pointer;
 *  If *query_io is 0 to start with then any query may be returned;
 *  If *query_io is !0 adns_query then only that query may be returned.
 *  If the call is successful, *query_io, *answer_r, and *context_r
 *  will all be set.
 * Errors:
 *  Return values are 0 or an errno value.
 *
 *  For _init, _init_strcfg, _submit and _synchronous, system errors
 *  (eg, failure to create sockets, malloc failure, etc.) return errno
 *  values.
 * 
 *  For _wait and _check failures are reported in the answer
 *  structure, and only 0, ESRCH or (for _check) EWOULDBLOCK is
 *  returned: if no (appropriate) requests are done adns_check returns
 *  EWOULDBLOCK; if no (appropriate) requests are outstanding both
 *  adns_query and adns_wait return ESRCH.
 *
 *  Additionally, _wait can return EINTR if you set adns_if_eintr.
 *
 *  All other errors (nameserver failure, timed out connections, &c)
 *  are returned in the status field of the answer.  After a
 *  successful _wait or _check, if status is nonzero then nrrs will be
 *  0, otherwise it will be >0.  type will always be the type
 *  requested.
 */

int adns_init(adns_state *newstate_r, adns_initflags flags,
	      FILE *diagfile /*0=>stderr*/);

int adns_init_strcfg(adns_state *newstate_r, adns_initflags flags,
		     FILE *diagfile /*0=>discard*/, const char *configtext);

int adns_synchronous(adns_state ads,
		     const char *owner,
		     adns_rrtype type,
		     adns_queryflags flags,
		     adns_answer **answer_r);

/* NB: if you set adns_if_noautosys then _submit and _check do not
 * make any system calls; you must use some of the asynch-io event
 * processing functions to actually get things to happen.
 */

int adns_submit(adns_state ads,
		const char *owner,
		adns_rrtype type,
		adns_queryflags flags,
		void *context,
		adns_query *query_r);

int adns_check(adns_state ads,
	       adns_query *query_io,
	       adns_answer **answer_r,
	       void **context_r);

int adns_wait(adns_state ads,
	      adns_query *query_io,
	      adns_answer **answer_r,
	      void **context_r);

void adns_cancel(adns_query query);

/* The adns_query you get back from _submit is valid (ie, can be
 * legitimately passed into adns functions) until it is returned by
 * adns_check or adns_wait, or passed to adns_cancel.  After that it
 * must not be used.  You can rely on it not being reused until the
 * first adns_submit or _transact call using the same adns_state after
 * it became invalid, so you may compare it for equality with other
 * query handles until you next call _query or _transact.
 *
 * _submit and _synchronous return ENOSYS if they don't understand the
 * query type.
 */

void adns_finish(adns_state ads);
/* You may call this even if you have queries outstanding;
 * they will be cancelled.
 */


void adns_forallqueries_begin(adns_state ads);
adns_query adns_forallqueries_next(adns_state ads, void **context_r);
/* Iterator functions, which you can use to loop over the outstanding
 * (submitted but not yet successfuly checked/waited) queries.
 *
 * You can only have one iteration going at once.  You may call _begin
 * at any time; after that, an iteration will be in progress.  You may
 * only call _next when an iteration is in progress - anything else
 * may coredump.  The iteration remains in progress until _next
 * returns 0, indicating that all the queries have been walked over,
 * or ANY other adns function is called with the same adns_state (or a
 * query in the same adns_state).  There is no need to explicitly
 * finish an iteration.
 *
 * context_r may be 0.  *context_r may not be set when _next returns 0.
 */

/*
 * Example expected/legal calling sequence for submit/check/wait:
 *  adns_init
 *  adns_submit 1
 *  adns_submit 2
 *  adns_submit 3
 *  adns_wait 1
 *  adns_check 3 -> EWOULDBLOCK
 *  adns_wait 2
 *  adns_wait 3
 *  ....
 *  adns_finish
 */

/*
 * Entrypoints for generic asynch io:
 * (these entrypoints are not very useful except in combination with *
 * some of the other I/O model calls which can tell you which fds to
 * be interested in):
 *
 * Note that any adns call may cause adns to open and close fds, so
 * you must call beforeselect or beforepoll again just before
 * blocking, or you may not have an up-to-date list of it's fds.
 */

int adns_processany(adns_state ads);
/* Gives adns flow-of-control for a bit.  This will never block, and
 * can be used with any threading/asynch-io model.  If some error
 * occurred which might cause an event loop to spin then the errno
 * value is returned.
 */

int adns_processreadable(adns_state ads, int fd, const struct timeval *now);
int adns_processwriteable(adns_state ads, int fd, const struct timeval *now);
int adns_processexceptional(adns_state ads, int fd, const struct timeval *now);
/* Gives adns flow-of-control so that it can process incoming data
 * from, or send outgoing data via, fd.  Very like _processany.  If it
 * returns zero then fd will no longer be readable or writeable
 * (unless of course more data has arrived since).  adns will _only_
 * that fd and only in the manner specified, regardless of whether
 * adns_if_noautosys was specified.
 *
 * adns_processexceptional should be called when select(2) reports an
 * exceptional condition, or poll(2) reports POLLPRI.
 *
 * It is fine to call _processreabable or _processwriteable when the
 * fd is not ready, or with an fd that doesn't belong to adns; it will
 * then just return 0.
 *
 * If some error occurred which might prevent an event loop to spin
 * then the errno value is returned.
 */

void adns_processtimeouts(adns_state ads, const struct timeval *now);
/* Gives adns flow-of-control so that it can process any timeouts
 * which might have happened.  Very like _processreadable/writeable.
 *
 * now may be 0; if it isn't, *now must be the current time, recently
 * obtained from gettimeofday.
 */

void adns_firsttimeout(adns_state ads,
		       struct timeval **tv_mod, struct timeval *tv_buf,
		       struct timeval now);
/* Asks adns when it would first like the opportunity to time
 * something out.  now must be the current time, from gettimeofday.
 * 
 * If tv_mod points to 0 then tv_buf must be non-null, and
 * _firsttimeout will fill in *tv_buf with the time until the first
 * timeout, and make *tv_mod point to tv_buf.  If adns doesn't have
 * anything that might need timing out it will leave *tv_mod as 0.
 *
 * If *tv_mod is not 0 then tv_buf is not used.  adns will update
 * *tv_mod if it has any earlier timeout, and leave it alone if it
 * doesn't.
 *
 * This call will not actually do any I/O, or change the fds that adns
 * is using.  It always succeeds and never blocks.
 */

void adns_globalsystemfailure(adns_state ads);
/* If serious problem(s) happen which globally affect your ability to
 * interact properly with adns, or adns's ability to function
 * properly, you or adns can call this function.
 *
 * All currently outstanding queries will be made to fail with
 * adns_s_systemfail, and adns will close any stream sockets it has
 * open.
 *
 * This is used by adns, for example, if gettimeofday() fails.
 * Without this the program's event loop might start to spin !
 *
 * This call will never block.
 */

/*
 * Entrypoints for select-loop based asynch io:
 */

void adns_beforeselect(adns_state ads, int *maxfd, fd_set *readfds,
		       fd_set *writefds, fd_set *exceptfds,
		       struct timeval **tv_mod, struct timeval *tv_buf,
		       const struct timeval *now);
/* Find out file descriptors adns is interested in, and when it would
 * like the opportunity to time something out.  If you do not plan to
 * block then tv_mod may be 0.  Otherwise, tv_mod and tv_buf are as
 * for adns_firsttimeout.  readfds, writefds, exceptfds and maxfd_io may
 * not be 0.
 *
 * If *now is not 0 then this will never actually do any I/O, or
 * change the fds that adns is using or the timeouts it wants.  In any
 * case it won't block.
 */

void adns_afterselect(adns_state ads, int maxfd, const fd_set *readfds,
		      const fd_set *writefds, const fd_set *exceptfds,
		      const struct timeval *now);
/* Gives adns flow-of-control for a bit; intended for use after
 * select.  This is just a fancy way of calling adns_processreadable/
 * writeable/timeouts as appropriate, as if select had returned the
 * data being passed.  Always succeeds.
 */

/*
 * Example calling sequence:
 *
 *  adns_init _noautosys
 *  loop {
 *   adns_beforeselect
 *   select
 *   adns_afterselect
 *   ...
 *   adns_submit / adns_check
 *   ...
 *  }
 */

/*
 * Entrypoints for poll-loop based asynch io:
 */

struct pollfd;
/* In case your system doesn't have it or you forgot to include
 * <sys/poll.h>, to stop the following declarations from causing
 * problems.  If your system doesn't have poll then the following
 * entrypoints will not be defined in libadns.  Sorry !
 */

int adns_beforepoll(adns_state ads, struct pollfd *fds, int *nfds_io, int *timeout_io,
		    const struct timeval *now);
/* Finds out which fd's adns is interested in, and when it would like
 * to be able to time things out.  This is in a form suitable for use
 * with poll(2).
 * 
 * On entry, usually fds should point to at least *nfds_io structs.
 * adns will fill up to that many structs will information for poll,
 * and record in *nfds_io how many structs it filled.  If it wants to
 * listen for more structs then *nfds_io will be set to the number
 * required and _beforepoll will return ERANGE.
 *
 * You may call _beforepoll with fds==0 and *nfds_io 0, in which case
 * adns will fill in the number of fds that it might be interested in
 * in *nfds_io, and always return either 0 (if it is not interested in
 * any fds) or ERANGE (if it is).
 *
 * NOTE that (unless timeout_io is 0) adns may acquire additional fds
 * from one call to the next, so you must put adns_beforepoll in a
 * loop, rather than assuming that the second call (with the buffer
 * size requested by the first) will not return ERANGE.
 *
 * adns only ever sets POLLIN, POLLOUT and POLLPRI in its pollfd
 * structs, and only ever looks at those bits.  POLLPRI is required to
 * detect TCP Urgent Data (which should not be used by a DNS server)
 * so that adns can know that the TCP stream is now useless.
 *
 * In any case, *timeout_io should be a timeout value as for poll(2),
 * which adns will modify downwards as required.  If the caller does
 * not plan to block then *timeout_io should be 0 on entry, or
 * alternatively, timeout_io may be 0.  (Alternatively, the caller may
 * use _beforeselect with timeout_io==0 to find out about file
 * descriptors, and use _firsttimeout is used to find out when adns
 * might want to time something out.)
 *
 * adns_beforepoll will return 0 on success, and will not fail for any
 * reason other than the fds buffer being too small (ERANGE).
 *
 * This call will never actually do any I/O, or change the fds that
 * adns is using or the timeouts it wants; and in any case it won't
 * block.
 */

#define ADNS_POLLFDS_RECOMMENDED 2
/* If you allocate an fds buf with at least RECOMMENDED entries then
 * you are unlikely to need to enlarge it.  You are recommended to do
 * so if it's convenient.  However, you must be prepared for adns to
 * require more space than this.
 */

void adns_afterpoll(adns_state ads, const struct pollfd *fds, int nfds,
		    const struct timeval *now);
/* Gives adns flow-of-control for a bit; intended for use after
 * poll(2).  fds and nfds should be the results from poll().  pollfd
 * structs mentioning fds not belonging to adns will be ignored.
 */


adns_status adns_rr_info(adns_rrtype type,
			 const char **rrtname_r, const char **fmtname_r,
			 int *len_r,
			 const void *datap, char **data_r);
/* Gets information in human-readable (but non-i18n) form
 * for eg debugging purposes.  type must be specified,
 * and the official name of the corresponding RR type will
 * be returned in *rrtname_r, and information about the processing
 * style in *fmtname_r.  The length of the table entry in an answer
 * for that type will be returned in in *len_r.
 * Any or all of rrtname_r, fmtname_r and len_r may be 0.
 * If fmtname_r is non-null then *fmtname_r may be
 * null on return, indicating that no special processing is
 * involved.
 *
 * data_r be must be non-null iff datap is.  In this case
 * *data_r will be set to point to a human-readable text
 * string representing the RR data.  The text will have
 * been obtained from malloc() and must be freed by the caller.
 *
 * Usually this routine will succeed.  Possible errors include:
 *  adns_s_nomemory
 *  adns_s_rrtypeunknown
 *  adns_s_invaliddata (*datap contained garbage)
 * If an error occurs then no memory has been allocated,
 * and *rrtname_r, *fmtname_r, *len_r and *data_r are undefined.
 */

const char *adns_strerror(adns_status st);
const char *adns_errabbrev(adns_status st);
/* Like strerror but for adns_status values.  adns_errabbrev returns
 * the abbreviation of the error - eg, for adns_s_timeout it returns
 * "timeout".  You MUST NOT call these functions with status values
 * not returned by the same adns library.
 */

#ifdef __cplusplus
} /* end of extern "C" */
#endif
#endif
