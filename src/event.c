/*
 * event.c
 * - event loop core
 * - TCP connection management
 * - user-visible check/wait and event-loop-related functions
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
 */

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "internal.h"

/* TCP connection management. */

void adns__tcp_closenext(adns_state ads) {
  int serv;
  
  serv= ads->tcpserver;
  close(ads->tcpsocket);
  ads->tcpstate= server_disconnected;
  ads->tcprecv.used= ads->tcpsend.used= 0;
  ads->tcpserver= (serv+1)%ads->nservers;
}

void adns__tcp_broken(adns_state ads, const char *what, const char *why) {
  int serv;
  adns_query qu, nqu;
  
  assert(ads->tcpstate == server_connecting || ads->tcpstate == server_ok);
  serv= ads->tcpserver;
  adns__warn(ads,serv,0,"TCP connection lost: %s: %s",what,why);
  adns__tcp_closenext(ads);
  
  for (qu= ads->timew.head; qu; qu= nqu) {
    nqu= qu->next;
    if (qu->state == query_udp) continue;
    assert(qu->state == query_tcpwait || qu->state == query_tcpsent);
    qu->state= query_tcpwait;
    qu->tcpfailed |= (1<<serv);
    if (qu->tcpfailed == (1<<ads->nservers)-1) {
      LIST_UNLINK(ads->timew,qu);
      adns__query_fail(qu,adns_s_allservfail);
    }
  }
}

static void tcp_connected(adns_state ads, struct timeval now) {
  adns_query qu, nqu;
  
  adns__debug(ads,ads->tcpserver,0,"TCP connected");
  ads->tcpstate= server_ok;
  for (qu= ads->timew.head; qu; qu= nqu) {
    nqu= qu->next;
    if (qu->state == query_udp) continue;
    assert (qu->state == query_tcpwait);
    adns__query_tcp(qu,now);
  }
}

void adns__tcp_tryconnect(adns_state ads, struct timeval now) {
  int r, fd, tries;
  struct sockaddr_in addr;
  struct protoent *proto;

  for (tries=0; tries<ads->nservers; tries++) {
    if (ads->tcpstate == server_connecting || ads->tcpstate == server_ok) return;
    assert(ads->tcpstate == server_disconnected);
    assert(!ads->tcpsend.used);
    assert(!ads->tcprecv.used);

    proto= getprotobyname("tcp");
    if (!proto) { adns__diag(ads,-1,0,"unable to find protocol no. for TCP !"); return; }
    fd= socket(AF_INET,SOCK_STREAM,proto->p_proto);
    if (fd<0) {
      adns__diag(ads,-1,0,"cannot create TCP socket: %s",strerror(errno));
      return;
    }
    r= adns__setnonblock(ads,fd);
    if (r) {
      adns__diag(ads,-1,0,"cannot make TCP socket nonblocking: %s",strerror(r));
      close(fd);
      return;
    }
    memset(&addr,0,sizeof(addr));
    addr.sin_family= AF_INET;
    addr.sin_port= htons(DNS_PORT);
    addr.sin_addr= ads->servers[ads->tcpserver].addr;
    r= connect(fd,(const struct sockaddr*)&addr,sizeof(addr));
    ads->tcpsocket= fd;
    ads->tcpstate= server_connecting;
    if (r==0) { tcp_connected(ads,now); continue; }
    if (errno == EWOULDBLOCK || errno == EINPROGRESS) return;
    adns__tcp_broken(ads,"connect",strerror(errno));
  }
}

/* Timeout handling functions. */

void adns__must_gettimeofday(adns_state ads, const struct timeval **now_io,
			     struct timeval *tv_buf) {
  const struct timeval *now;
  int r;

  now= *now_io;
  if (now) return;
  r= gettimeofday(tv_buf,0); if (!r) { *now_io= tv_buf; return; }
  adns__diag(ads,-1,0,"gettimeofday failed: %s",strerror(errno));
  adns_globalsystemfailure(ads);
  return;
}

static void inter_maxto(struct timeval **tv_io, struct timeval *tvbuf,
			struct timeval maxto) {
  struct timeval *rbuf;

  if (!tv_io) return;
  rbuf= *tv_io;
  if (!rbuf) {
    *tvbuf= maxto; *tv_io= tvbuf;
  } else {
    if (timercmp(rbuf,&maxto,>)) *rbuf= maxto;
  }
/*fprintf(stderr,"inter_maxto maxto=%ld.%06ld result=%ld.%06ld\n",
	maxto.tv_sec,maxto.tv_usec,(**tv_io).tv_sec,(**tv_io).tv_usec);*/
}

static void inter_maxtoabs(struct timeval **tv_io, struct timeval *tvbuf,
			   struct timeval now, struct timeval maxtime) {
  ldiv_t dr;

/*fprintf(stderr,"inter_maxtoabs now=%ld.%06ld maxtime=%ld.%06ld\n",
	now.tv_sec,now.tv_usec,maxtime.tv_sec,maxtime.tv_usec);*/
  if (!tv_io) return;
  maxtime.tv_sec -= (now.tv_sec+2);
  maxtime.tv_usec -= (now.tv_usec-2000000);
  dr= ldiv(maxtime.tv_usec,1000000);
  maxtime.tv_sec += dr.quot;
  maxtime.tv_usec -= dr.quot*1000000;
  if (maxtime.tv_sec<0) timerclear(&maxtime);
  inter_maxto(tv_io,tvbuf,maxtime);
}

void adns__timeouts(adns_state ads, int act,
		    struct timeval **tv_io, struct timeval *tvbuf,
		    struct timeval now) {
  adns_query qu, nqu;

  for (qu= ads->timew.head; qu; qu= nqu) {
    nqu= qu->next;
    if (timercmp(&now,&qu->timeout,<=)) {
      if (!tv_io) continue;
      inter_maxtoabs(tv_io,tvbuf,now,qu->timeout);
    } else {
      if (!act) continue;
      LIST_UNLINK(ads->timew,qu);
      if (qu->state != query_udp) {
	adns__query_fail(qu,adns_s_timeout);
      } else {
	adns__query_udp(qu,now);
      }
      nqu= ads->timew.head;
    }
  }
}  

void adns_firsttimeout(adns_state ads,
		       struct timeval **tv_io, struct timeval *tvbuf,
		       struct timeval now) {
  adns__timeouts(ads, 0, tv_io,tvbuf, now);
}

void adns_processtimeouts(adns_state ads, const struct timeval *now) {
  struct timeval tv_buf;

  adns__must_gettimeofday(ads,&now,&tv_buf); if (!now) return;
  adns__timeouts(ads, 1, 0,0, *now);
}

/* fd handling functions.  These are the top-level of the real work of
 * reception and often transmission.
 */

int adns__pollfds(adns_state ads, struct pollfd pollfds_buf[MAX_POLLFDS]) {
  /* Returns the number of entries filled in.  Always zeroes revents. */

  assert(MAX_POLLFDS==2);

  pollfds_buf[0].fd= ads->udpsocket;
  pollfds_buf[0].events= POLLIN;
  pollfds_buf[0].revents= 0;

  switch (ads->tcpstate) {
  case server_disconnected:
    return 1;
  case server_connecting:
    pollfds_buf[1].events= POLLOUT;
    break;
  case server_ok:
    pollfds_buf[1].events= ads->tcpsend.used ? POLLIN|POLLOUT|POLLPRI : POLLIN|POLLPRI;
    break;
  default:
    abort();
  }
  pollfds_buf[1].fd= ads->tcpsocket;
  return 2;
}

int adns_processreadable(adns_state ads, int fd, const struct timeval *now) {
  int skip, want, dgramlen, r, udpaddrlen, serv;
  byte udpbuf[DNS_MAXUDP];
  struct sockaddr_in udpaddr;
  
  switch (ads->tcpstate) {
  case server_disconnected:
  case server_connecting:
    break;
  case server_ok:
    if (fd != ads->tcpsocket) break;
    skip= 0;
    for (;;) {
      if (ads->tcprecv.used<skip+2) {
	want= 2;
      } else {
	dgramlen= (ads->tcprecv.buf[skip]<<8) | ads->tcprecv.buf[skip+1];
	if (ads->tcprecv.used<skip+2+dgramlen) {
	  want= 2+dgramlen;
	} else {
	  adns__procdgram(ads,ads->tcprecv.buf+skip+2,dgramlen,ads->tcpserver,*now);
	  skip+= 2+dgramlen; continue;
	}
      }
      ads->tcprecv.used -= skip;
      memmove(ads->tcprecv.buf,ads->tcprecv.buf+skip,ads->tcprecv.used);
      skip= 0;
      if (!adns__vbuf_ensure(&ads->tcprecv,want)) return ENOMEM;
      assert(ads->tcprecv.used <= ads->tcprecv.avail);
      if (ads->tcprecv.used == ads->tcprecv.avail) continue;
      r= read(ads->tcpsocket,
	      ads->tcprecv.buf+ads->tcprecv.used,
	      ads->tcprecv.avail-ads->tcprecv.used);
      if (r>0) {
	ads->tcprecv.used+= r;
      } else {
	if (r) {
	  if (errno==EAGAIN || errno==EWOULDBLOCK) return 0;
	  if (errno==EINTR) continue;
	  if (errno_resources(errno)) return errno;
	}
	adns__tcp_broken(ads,"read",r?strerror(errno):"closed");
	return 0;
      }
    } /* never reached */
  default:
    abort();
  }
  if (fd == ads->udpsocket) {
    for (;;) {
      udpaddrlen= sizeof(udpaddr);
      r= recvfrom(ads->udpsocket,udpbuf,sizeof(udpbuf),0,
		  (struct sockaddr*)&udpaddr,&udpaddrlen);
      if (r<0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
	if (errno == EINTR) continue;
	if (errno_resources(errno)) return errno;
	adns__warn(ads,-1,0,"datagram receive error: %s",strerror(errno));
	return 0;
      }
      if (udpaddrlen != sizeof(udpaddr)) {
	adns__diag(ads,-1,0,"datagram received with wrong address length %d"
		   " (expected %d)", udpaddrlen,sizeof(udpaddr));
	continue;
      }
      if (udpaddr.sin_family != AF_INET) {
	adns__diag(ads,-1,0,"datagram received with wrong protocol family"
		   " %u (expected %u)",udpaddr.sin_family,AF_INET);
	continue;
      }
      if (ntohs(udpaddr.sin_port) != DNS_PORT) {
	adns__diag(ads,-1,0,"datagram received from wrong port %u (expected %u)",
		   ntohs(udpaddr.sin_port),DNS_PORT);
	continue;
      }
      for (serv= 0;
	   serv < ads->nservers &&
	     ads->servers[serv].addr.s_addr != udpaddr.sin_addr.s_addr;
	   serv++);
      if (serv >= ads->nservers) {
	adns__warn(ads,-1,0,"datagram received from unknown nameserver %s",
		   inet_ntoa(udpaddr.sin_addr));
	continue;
      }
      adns__procdgram(ads,udpbuf,r,serv,*now);
    }
  }
  return 0;
}

int adns_processwriteable(adns_state ads, int fd, const struct timeval *now) {
  int r;
  
  switch (ads->tcpstate) {
  case server_disconnected:
    break;
  case server_connecting:
    if (fd != ads->tcpsocket) break;
    assert(ads->tcprecv.used==0);
    for (;;) {
      if (!adns__vbuf_ensure(&ads->tcprecv,1)) return ENOMEM;
      r= read(ads->tcpsocket,&ads->tcprecv.buf,1);
      if (r==0 || (r<0 && (errno==EAGAIN || errno==EWOULDBLOCK))) {
	tcp_connected(ads,*now);
	return 0;
      }
      if (r>0) {
	adns__tcp_broken(ads,"connect/read","sent data before first request");
	return 0;
      }
      if (errno==EINTR) continue;
      if (errno_resources(errno)) return errno;
      adns__tcp_broken(ads,"connect/read",strerror(errno));
      return 0;
    } /* not reached */
  case server_ok:
    if (!(ads->tcpsend.used && fd == ads->tcpsocket)) break;
    for (;;) {
      adns__sigpipe_protect(ads);
      r= write(ads->tcpsocket,ads->tcpsend.buf,ads->tcpsend.used);
      adns__sigpipe_unprotect(ads);
      if (r<0) {
	if (errno==EINTR) continue;
	if (errno==EAGAIN || errno==EWOULDBLOCK) return 0;
	if (errno_resources(errno)) return errno;
	adns__tcp_broken(ads,"write",strerror(errno));
	return 0;
      } else if (r>0) {
	ads->tcpsend.used -= r;
	memmove(ads->tcpsend.buf,ads->tcpsend.buf+r,ads->tcpsend.used);
      }
    } /* not reached */
  default:
    abort();
  }
  return 0;
}
  
int adns_processexceptional(adns_state ads, int fd, const struct timeval *now) {
  switch (ads->tcpstate) {
  case server_disconnected:
    break;
  case server_connecting:
  case server_ok:
    if (fd != ads->tcpsocket) break;
    adns__tcp_broken(ads,"poll/select","exceptional condition detected");
    return 0;
  default:
    abort();
  }
  return 0;
}

static void fd_event(adns_state ads, int fd,
		     int revent, int pollflag,
		     int maxfd, const fd_set *fds,
		     int (*func)(adns_state, int fd, const struct timeval *now),
		     struct timeval now, int *r_r) {
  int r;
  
  if (!(revent & pollflag)) return;
  if (fds && !(fd<maxfd && FD_ISSET(fd,fds))) return;
  r= func(ads,fd,&now);
  if (r) {
    if (r_r) {
      *r_r= r;
    } else {
      adns__diag(ads,-1,0,"process fd failed after select: %s",strerror(errno));
      adns_globalsystemfailure(ads);
    }
  }
}

void adns__fdevents(adns_state ads,
		    const struct pollfd *pollfds, int npollfds,
		    int maxfd, const fd_set *readfds,
		    const fd_set *writefds, const fd_set *exceptfds,
		    struct timeval now, int *r_r) {
  int i, fd, revents;

  for (i=0; i<npollfds; i++) {
    fd= pollfds[i].fd;
    if (fd >= maxfd) maxfd= fd+1;
    revents= pollfds[i].revents;
    fd_event(ads,fd, revents,POLLIN, maxfd,readfds, adns_processreadable,now,r_r);
    fd_event(ads,fd, revents,POLLOUT, maxfd,writefds, adns_processwriteable,now,r_r);
    fd_event(ads,fd, revents,POLLPRI, maxfd,exceptfds, adns_processexceptional,now,r_r);
  }
}

/* Wrappers for select(2). */

void adns_beforeselect(adns_state ads, int *maxfd_io, fd_set *readfds_io,
		       fd_set *writefds_io, fd_set *exceptfds_io,
		       struct timeval **tv_mod, struct timeval *tv_tobuf,
		       const struct timeval *now) {
  struct timeval tv_nowbuf;
  struct pollfd pollfds[MAX_POLLFDS];
  int i, fd, maxfd, npollfds;
  
  if (tv_mod && (!*tv_mod || (*tv_mod)->tv_sec || (*tv_mod)->tv_usec)) {
    /* The caller is planning to sleep. */
    adns__must_gettimeofday(ads,&now,&tv_nowbuf);
    if (!now) return;
    adns__timeouts(ads, 1, tv_mod,tv_tobuf, *now);
  }

  npollfds= adns__pollfds(ads,pollfds);
  maxfd= *maxfd_io;
  for (i=0; i<npollfds; i++) {
    fd= pollfds[i].fd;
    if (fd >= maxfd) maxfd= fd+1;
    if (pollfds[i].events & POLLIN) FD_SET(fd,readfds_io);
    if (pollfds[i].events & POLLOUT) FD_SET(fd,writefds_io);
    if (pollfds[i].events & POLLPRI) FD_SET(fd,exceptfds_io);
  }
  *maxfd_io= maxfd;
}

void adns_afterselect(adns_state ads, int maxfd, const fd_set *readfds,
		      const fd_set *writefds, const fd_set *exceptfds,
		      const struct timeval *now) {
  struct timeval tv_buf;
  struct pollfd pollfds[MAX_POLLFDS];
  int npollfds, i;

  adns__must_gettimeofday(ads,&now,&tv_buf);
  if (!now) return;
  adns_processtimeouts(ads,now);

  npollfds= adns__pollfds(ads,pollfds);
  for (i=0; i<npollfds; i++) pollfds[i].revents= POLLIN|POLLOUT|POLLPRI;
  adns__fdevents(ads,
		 pollfds,npollfds,
		 maxfd,readfds,writefds,exceptfds,
		 *now, 0);
}

/* General helpful functions. */

void adns_globalsystemfailure(adns_state ads) {
  while (ads->timew.head) {
    adns__query_fail(ads->timew.head, adns_s_systemfail);
  }
  
  switch (ads->tcpstate) {
  case server_connecting:
  case server_ok:
    adns__tcp_closenext(ads);
    break;
  case server_disconnected:
    break;
  default:
    abort();
  }
}

int adns_processany(adns_state ads) {
  int r;
  struct timeval now;
  struct pollfd pollfds[MAX_POLLFDS];
  int npollfds;

  r= gettimeofday(&now,0);
  if (!r) adns_processtimeouts(ads,&now);

  npollfds= adns__pollfds(ads,pollfds);
  adns__fdevents(ads,
		 pollfds,npollfds,
		 0,0,0,0,
		 now,&r);
  return r;
}

void adns__autosys(adns_state ads, struct timeval now) {
  if (ads->iflags & adns_if_noautosys) return;
  adns_processany(ads);
}

static int internal_check(adns_state ads,
			  adns_query *query_io,
			  adns_answer **answer,
			  void **context_r) {
  adns_query qu;

  qu= *query_io;
  if (!qu) {
    if (!ads->output.head) return EWOULDBLOCK;
    qu= ads->output.head;
  } else {
    if (qu->id>=0) return EWOULDBLOCK;
  }
  LIST_UNLINK(ads->output,qu);
  *answer= qu->answer;
  if (context_r) *context_r= qu->ctx.ext;
  *query_io= qu;
  free(qu);
  return 0;
}

int adns_wait(adns_state ads,
	      adns_query *query_io,
	      adns_answer **answer_r,
	      void **context_r) {
  int r, maxfd, rsel;
  fd_set readfds, writefds, exceptfds;
  struct timeval tvbuf, *tvp;
  
  for (;;) {
    r= internal_check(ads,query_io,answer_r,context_r);
    if (r != EWOULDBLOCK) return r;
    maxfd= 0; tvp= 0;
    FD_ZERO(&readfds); FD_ZERO(&writefds); FD_ZERO(&exceptfds);
    adns_beforeselect(ads,&maxfd,&readfds,&writefds,&exceptfds,&tvp,&tvbuf,0);
    rsel= select(maxfd,&readfds,&writefds,&exceptfds,tvp);
    if (rsel==-1) {
      if (errno == EINTR) {
	if (ads->iflags & adns_if_eintr) return EINTR;
      } else {
	adns__diag(ads,-1,0,"select failed in wait: %s",strerror(errno));
	adns_globalsystemfailure(ads);
      }
    } else {
      assert(rsel >= 0);
      adns_afterselect(ads,maxfd,&readfds,&writefds,&exceptfds,0);
    }
  }
}

int adns_check(adns_state ads,
	       adns_query *query_io,
	       adns_answer **answer_r,
	       void **context_r) {
  struct timeval now;
  int r;
  
  r= gettimeofday(&now,0);
  if (!r) adns__autosys(ads,now);
  
  return internal_check(ads,query_io,answer_r,context_r);
}
