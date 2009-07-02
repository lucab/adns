#ifndef HARNESS_H_INCLUDED
#define HARNESS_H_INCLUDED
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include "internal.h"
#ifdef HAVE_POLL
#include <sys/poll.h>
#endif
/* We override several system calls with #define's */
int Hselect(
	int max , fd_set *rfds , fd_set *wfds , fd_set *efds , struct timeval *to 
	);
#ifdef HAVE_POLL
int Hpoll(
	struct pollfd *fds , int nfds , int timeout 
	);
#endif
int Hsocket(
	int domain , int type , int protocol 
	);
int Hfcntl(
	int fd , int cmd , ... 
	);
int Hconnect(
	int fd , const struct sockaddr *addr , int addrlen 
	);
int Hclose(
	int fd 
	);
int Hsendto(
	int fd , const void *msg , int msglen , unsigned int flags , const struct sockaddr *addr , int addrlen 
	);
int Hrecvfrom(
	int fd , void *buf , int buflen , unsigned int flags , struct sockaddr *addr , int *addrlen 
	);
int Hread(
	int fd , void *buf , size_t buflen 
	);
int Hwrite(
	int fd , const void *buf , size_t len 
	);
int Hwritev(int fd, const struct iovec *vector, size_t count);
int Hgettimeofday(struct timeval *tv, struct timezone *tz);
void *Hmalloc(size_t sz);
void Hfree(void *ptr);
void *Hrealloc(void *op, size_t nsz);
void Hexit(int rv);
/* There is a Q function (Q for Question) for each such syscall;
 * it constructs a string representing the call, and calls Q_str
 * on it, or constructs it in vb and calls Q_vb;
 */
void Qselect(
	int max , const fd_set *rfds , const fd_set *wfds , const fd_set *efds , struct timeval *to 
	);
#ifdef HAVE_POLL
void Qpoll(
	const struct pollfd *fds , int nfds , int timeout 
	);
#endif
void Qsocket(
	 int type 
	);
void Qfcntl(
	int fd , int cmd , long arg 
	);
void Qconnect(
	int fd , const struct sockaddr *addr , int addrlen 
	);
void Qclose(
	int fd 
	);
void Qsendto(
	int fd , const void *msg , int msglen , const struct sockaddr *addr , int addrlen 
	);
void Qrecvfrom(
	int fd , int buflen , int addrlen 
	);
void Qread(
	int fd , size_t buflen 
	);
void Qwrite(
	int fd , const void *buf , size_t len 
	);
void Q_vb(void);
extern void Tshutdown(void);
/* General help functions */
void Tfailed(const char *why);
void Toutputerr(void);
void Tnomem(void);
void Tfsyscallr(const char *fmt, ...) PRINTFFORMAT(1,2);
void Tensureoutputfile(void);
void Tmust(const char *call, const char *arg, int cond);
void Tvbf(const char *fmt, ...) PRINTFFORMAT(1,2);
void Tvbvf(const char *fmt, va_list al);
void Tvbfdset(int max, const fd_set *set);
void Tvbpollfds(const struct pollfd *fds, int nfds);
void Tvbaddr(const struct sockaddr *addr, int addrlen);
void Tvbbytes(const void *buf, int len);
void Tvberrno(int e);
void Tvba(const char *str);
/* Shared globals */
extern vbuf vb;
extern struct timeval currenttime;
extern const struct Terrno { const char *n; int v; } Terrnos[];
#endif
