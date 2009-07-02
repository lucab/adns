#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "harness.h"
#include "internal.h"
vbuf vb;
FILE *Toutputfile= 0;
struct timeval currenttime;
const struct Terrno Terrnos[]= {
  { "EAGAIN",                    EAGAIN                       },
  { "EINPROGRESS",               EINPROGRESS                  },
  { "EINTR",                     EINTR                        },
  { "EINVAL",                    EINVAL                       },
  { "EMSGSIZE",                  EMSGSIZE                     },
  { "ENOBUFS",                   ENOBUFS                      },
  { "ENOENT",                    ENOENT                       },
  { "ENOPROTOOPT",               ENOPROTOOPT                  },
  { "ENOSPC",                    ENOSPC                       },
  { "EWOULDBLOCK",               EWOULDBLOCK                  },
  {  0,                          0                            }
};
static vbuf vbw;
int Hgettimeofday(struct timeval *tv, struct timezone *tz) {
  Tmust("gettimeofday","tz",!tz);
  *tv= currenttime;
  return 0;
}
int Hwritev(int fd, const struct iovec *vector, size_t count) {
  size_t i;
  vbw.used= 0;
  for (i=0; i<count; i++, vector++) {
    if (!adns__vbuf_append(&vbw,vector->iov_base,vector->iov_len)) Tnomem();
  }
  return Hwrite(fd,vbw.buf,vbw.used);
}
void Qselect(
	int max , const fd_set *rfds , const fd_set *wfds , const fd_set *efds , struct timeval *to 
	) {
 vb.used= 0;
 Tvba("select");
	Tvbf(" max=%d",max); 
	Tvbf(" rfds="); Tvbfdset(max,rfds); 
	Tvbf(" wfds="); Tvbfdset(max,wfds); 
	Tvbf(" efds="); Tvbfdset(max,efds); 
  if (to) Tvbf(" to=%ld.%06ld",(long)to->tv_sec,(long)to->tv_usec);
  else Tvba(" to=null"); 
  Q_vb();
}
#ifdef HAVE_POLL
void Qpoll(
	const struct pollfd *fds , int nfds , int timeout 
	) {
 vb.used= 0;
 Tvba("poll");
        Tvbf(" fds="); Tvbpollfds(fds,nfds); 
	Tvbf(" timeout=%d",timeout); 
  Q_vb();
}
#endif
void Qsocket(
	 int type 
	) {
 vb.used= 0;
 Tvba("socket");
  Tvbf(type==SOCK_STREAM ? " type=SOCK_STREAM" : " type=SOCK_DGRAM"); 
  Q_vb();
}
void Qfcntl(
	int fd , int cmd , long arg 
	) {
 vb.used= 0;
 Tvba("fcntl");
	Tvbf(" fd=%d",fd); 
  if (cmd == F_SETFL) {
   Tvbf(" cmd=F_SETFL %s",arg & O_NONBLOCK ? "O_NONBLOCK|..." : "~O_NONBLOCK&...");
  } else if (cmd == F_GETFL) {
   Tvba(" cmd=F_GETFL");
  } else {
   Tmust("cmd","F_GETFL/F_SETFL",0);
  } 
  Q_vb();
}
void Qconnect(
	int fd , const struct sockaddr *addr , int addrlen 
	) {
 vb.used= 0;
 Tvba("connect");
	Tvbf(" fd=%d",fd); 
	Tvba(" addr="); Tvbaddr(addr,addrlen); 
  Q_vb();
}
void Qclose(
	int fd 
	) {
 vb.used= 0;
 Tvba("close");
	Tvbf(" fd=%d",fd); 
  Q_vb();
}
void Qsendto(
	int fd , const void *msg , int msglen , const struct sockaddr *addr , int addrlen 
	) {
 vb.used= 0;
 Tvba("sendto");
	Tvbf(" fd=%d",fd); 
	Tvba(" addr="); Tvbaddr(addr,addrlen); 
	Tvbbytes(msg,msglen); 
  Q_vb();
}
void Qrecvfrom(
	int fd , int buflen , int addrlen 
	) {
 vb.used= 0;
 Tvba("recvfrom");
	Tvbf(" fd=%d",fd); 
	Tvbf(" buflen=%lu",(unsigned long)buflen); 
	Tvbf(" *addrlen=%d",addrlen); 
  Q_vb();
}
void Qread(
	int fd , size_t buflen 
	) {
 vb.used= 0;
 Tvba("read");
	Tvbf(" fd=%d",fd); 
	Tvbf(" buflen=%lu",(unsigned long)buflen); 
  Q_vb();
}
void Qwrite(
	int fd , const void *buf , size_t len 
	) {
 vb.used= 0;
 Tvba("write");
	Tvbf(" fd=%d",fd); 
	Tvbbytes(buf,len); 
  Q_vb();
}
void Tvbaddr(const struct sockaddr *addr, int len) {
  const struct sockaddr_in *ai= (const struct sockaddr_in*)addr;
  assert(len==sizeof(struct sockaddr_in));
  assert(ai->sin_family==AF_INET);
  Tvbf("%s:%u",inet_ntoa(ai->sin_addr),htons(ai->sin_port));
}
void Tvbbytes(const void *buf, int len) {
  const byte *bp;
  int i;
  if (!len) { Tvba(" empty"); return; }
  for (i=0, bp=buf; i<len; i++, bp++) {
    if (!(i&31)) Tvba("\n     ");
    else if (!(i&3)) Tvba(" ");
    Tvbf("%02x",*bp);
  }
  Tvba(".");
}
void Tvbfdset(int max, const fd_set *fds) {
  int i;
  const char *comma= "";
  Tvba("[");
  for (i=0; i<max; i++) {
    if (!FD_ISSET(i,fds)) continue;
    Tvba(comma);
    Tvbf("%d",i);
    comma= ",";
  }
  Tvba("]");
}
static void Tvbpollevents(int events) {
  const char *delim= "";
  events &= (POLLIN|POLLOUT|POLLPRI);
  if (!events) { Tvba("0"); return; }
  if (events & POLLIN) { Tvba("POLLIN"); delim= "|"; }
  if (events & POLLOUT) { Tvba(delim); Tvba("POLLOUT"); delim= "|"; }
  if (events & POLLPRI) { Tvba(delim); Tvba("POLLPRI"); }
}
void Tvbpollfds(const struct pollfd *fds, int nfds) {
  const char *comma= "";
  Tvba("[");
  while (nfds>0) {
    Tvba(comma);
    Tvbf("{fd=%d, events=",fds->fd);
    Tvbpollevents(fds->events);
    Tvba(", revents=");
    Tvbpollevents(fds->revents);
    Tvba("}");
    comma= ", ";
    nfds--; fds++;
  }
  Tvba("]");
}
void Tvberrno(int e) {
  const struct Terrno *te;
  for (te= Terrnos; te->n && te->v != e; te++);
  if (te->n) Tvba(te->n);
  else Tvbf("E#%d",e);
}
void Tvba(const char *str) {
  if (!adns__vbuf_appendstr(&vb,str)) Tnomem();
}
void Tvbvf(const char *fmt, va_list al) {
  char buf[1000];
  buf[sizeof(buf)-2]= '\t';
  vsnprintf(buf,sizeof(buf),fmt,al);
  assert(buf[sizeof(buf)-2] == '\t');
  Tvba(buf);
}
void Tvbf(const char *fmt, ...) {
  va_list al;
  va_start(al,fmt);
  Tvbvf(fmt,al);
  va_end(al);
}
void Tmust(const char *call, const char *arg, int cond) {
  if (cond) return;
  fprintf(stderr,"adns test harness: case not handled: system call %s, arg %s",call,arg);
  exit(-1);
}
void Tfailed(const char *why) {
  fprintf(stderr,"adns test harness: failure: %s: %s\n",why,strerror(errno));
  exit(-1);
}
void Tnomem(void) {
  Tfailed("unable to malloc/realloc");
}
void Toutputerr(void) {
  Tfailed("write error on test harness output");
}
