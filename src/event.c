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

#include <netdb.h>
#include <arpa/inet.h>

#include "internal.h"

/* TCP connection management */

void adns__tcp_broken(adns_state ads, const char *what, const char *why) {
  int serv;
  adns_query qu, nqu;
  
  assert(ads->tcpstate == server_connecting || ads->tcpstate == server_ok);
  serv= ads->tcpserver;
  adns__warn(ads,serv,0,"TCP connection lost: %s: %s",what,why);
  close(ads->tcpsocket);
  ads->tcpstate= server_disconnected;
  
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

  ads->tcprecv.used= ads->tcpsend.used= 0;
  ads->tcpserver= (serv+1)%ads->nservers;
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
    r= connect(fd,&addr,sizeof(addr));
    ads->tcpsocket= fd;
    ads->tcpstate= server_connecting;
    if (r==0) { tcp_connected(ads,now); continue; }
    if (errno == EWOULDBLOCK || errno == EINPROGRESS) return;
    adns__tcp_broken(ads,"connect",strerror(errno));
  }
}

/* `Interest' functions - find out which fd's we might be interested in,
 * and when we want to be called back for a timeout.
 */

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

static void inter_addfd(int *maxfd, fd_set *fds, int fd) {
  if (!maxfd || !fds) return;
  if (fd>=*maxfd) *maxfd= fd+1;
  FD_SET(fd,fds);
}

static void checktimeouts(adns_state ads, struct timeval now,
			  struct timeval **tv_io, struct timeval *tvbuf) {
  adns_query qu, nqu;
  
  for (qu= ads->timew.head; qu; qu= nqu) {
    nqu= qu->next;
    if (timercmp(&now,&qu->timeout,>)) {
      LIST_UNLINK(ads->timew,qu);
      if (qu->state != query_udp) {
	adns__query_fail(qu,adns_s_timeout);
      } else {
	adns__query_udp(qu,now);
      }
    } else {
      inter_maxtoabs(tv_io,tvbuf,now,qu->timeout);
    }
  }
}  
 
void adns_interest(adns_state ads, int *maxfd,
		   fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		   struct timeval **tv_io, struct timeval *tvbuf) {
  struct timeval now;
  struct timeval tvto_lr;
  int r;
  
/*fprintf(stderr,"adns_interest\n");*/

  r= gettimeofday(&now,0);
  if (r) {
    adns__warn(ads,-1,0,"gettimeofday failed - will sleep for a bit: %s",
	       strerror(errno));
    timerclear(&tvto_lr); timevaladd(&tvto_lr,LOCALRESOURCEMS);
    inter_maxto(tv_io, tvbuf, tvto_lr);
  } else {
    checktimeouts(ads,now,tv_io,tvbuf);
  }
  
  inter_addfd(maxfd,readfds,ads->udpsocket);

  switch (ads->tcpstate) {
  case server_disconnected:
    break;
  case server_connecting:
    inter_addfd(maxfd,writefds,ads->tcpsocket);
    break;
  case server_ok:
    inter_addfd(maxfd,readfds,ads->tcpsocket);
    inter_addfd(maxfd,exceptfds,ads->tcpsocket);
    if (ads->tcpsend.used) inter_addfd(maxfd,writefds,ads->tcpsocket);
    break;
  default:
    abort();
  }
}

/* Callback procedures - these do the real work of reception and timeout, etc. */

static int callb_checkfd(int maxfd, const fd_set *fds, int fd) {
  return maxfd<0 || !fds ? 1 :
         fd<maxfd && FD_ISSET(fd,fds);
}

static int internal_callback(adns_state ads, int maxfd,
			     const fd_set *readfds, const fd_set *writefds,
			     const fd_set *exceptfds,
			     struct timeval now) {
  int skip, want, dgramlen, count, udpaddrlen, r, serv;
  byte udpbuf[DNS_MAXUDP];
  struct sockaddr_in udpaddr;

  count= 0;

  switch (ads->tcpstate) {
  case server_disconnected:
    break;
  case server_connecting:
    if (callb_checkfd(maxfd,writefds,ads->tcpsocket)) {
      count++;
      assert(ads->tcprecv.used==0);
      if (!adns__vbuf_ensure(&ads->tcprecv,1)) return -1;
      if (ads->tcprecv.buf) {
	r= read(ads->tcpsocket,&ads->tcprecv.buf,1);
	if (r==0 || (r<0 && (errno==EAGAIN || errno==EWOULDBLOCK))) {
	  tcp_connected(ads,now);
	} else if (r>0) {
	  adns__tcp_broken(ads,"connect/read","sent data before first request");
	} else if (errno!=EINTR) {
	  adns__tcp_broken(ads,"connect/read",strerror(errno));
	}
      }
    }
    break;
  case server_ok:
    count+= callb_checkfd(maxfd,readfds,ads->tcpsocket) +
            callb_checkfd(maxfd,exceptfds,ads->tcpsocket) +
      (ads->tcpsend.used && callb_checkfd(maxfd,writefds,ads->tcpsocket));
    if (callb_checkfd(maxfd,readfds,ads->tcpsocket)) {
      skip= 0;
      for (;;) {
	if (ads->tcprecv.used<skip+2) {
	  want= 2;
	} else {
	  dgramlen= (ads->tcprecv.buf[skip]<<8) | ads->tcprecv.buf[skip+1];
	  if (ads->tcprecv.used<skip+2+dgramlen) {
	    want= 2+dgramlen;
	  } else {
	    adns__procdgram(ads,ads->tcprecv.buf+skip+2,dgramlen,ads->tcpserver,now);
	    skip+= 2+dgramlen; continue;
	  }
	}
	ads->tcprecv.used -= skip;
	memmove(ads->tcprecv.buf,ads->tcprecv.buf+skip,ads->tcprecv.used);
	skip= 0;
	if (!adns__vbuf_ensure(&ads->tcprecv,want)) return -1;
	assert(ads->tcprecv.used <= ads->tcprecv.avail);
	if (ads->tcprecv.used == ads->tcprecv.avail) continue;
	r= read(ads->tcpsocket,
		ads->tcprecv.buf+ads->tcprecv.used,
		ads->tcprecv.avail-ads->tcprecv.used);
	if (r>0) {
	  ads->tcprecv.used+= r;
	} else {
	  if (r<0) {
	    if (errno==EAGAIN || errno==EWOULDBLOCK || errno==ENOMEM) break;
	    if (errno==EINTR) continue;
	  }
	  adns__tcp_broken(ads,"read",r?strerror(errno):"closed");
	  break;
	}
      }
    } else if (callb_checkfd(maxfd,exceptfds,ads->tcpsocket)) {
      adns__tcp_broken(ads,"select","exceptional condition detected");
    } else if (ads->tcpsend.used && callb_checkfd(maxfd,writefds,ads->tcpsocket)) {
      adns__sigpipe_protect(ads);
      r= write(ads->tcpsocket,ads->tcpsend.buf,ads->tcpsend.used);
      adns__sigpipe_unprotect(ads);
      if (r<0) {
	if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=ENOMEM && errno!=EINTR) {
	  adns__tcp_broken(ads,"write",strerror(errno));
	}
      } else if (r>0) {
	ads->tcpsend.used -= r;
	memmove(ads->tcpsend.buf,ads->tcpsend.buf+r,ads->tcpsend.used);
      }
    }
    break;
  default:
    abort();
  }

  if (callb_checkfd(maxfd,readfds,ads->udpsocket)) {
    count++;
    for (;;) {
      udpaddrlen= sizeof(udpaddr);
      r= recvfrom(ads->udpsocket,udpbuf,sizeof(udpbuf),0,&udpaddr,&udpaddrlen);
      if (r<0) {
	if (!(errno == EAGAIN || errno == EWOULDBLOCK ||
	      errno == EINTR || errno == ENOMEM || errno == ENOBUFS))
	  adns__warn(ads,-1,0,"datagram receive error: %s",strerror(errno));
	break;
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
      adns__procdgram(ads,udpbuf,r,serv,now);
    }
  }
  return count;
}

int adns_callback(adns_state ads, int maxfd,
		  const fd_set *readfds, const fd_set *writefds,
		  const fd_set *exceptfds) {
  struct timeval now;
  int r;

  r= gettimeofday(&now,0); if (r) return -1;
  checktimeouts(ads,now,0,0);
  return internal_callback(ads,maxfd,readfds,writefds,exceptfds,now);
}

/* User-visible functions and their implementation. */

void adns__autosys(adns_state ads, struct timeval now) {
  if (ads->iflags & adns_if_noautosys) return;
  adns_callback(ads,-1,0,0,0);
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
  free(qu);
  return 0;
}

int adns_wait(adns_state ads,
	      adns_query *query_io,
	      adns_answer **answer_r,
	      void **context_r) {
  int r, maxfd, rsel, rcb;
  fd_set readfds, writefds, exceptfds;
  struct timeval tvbuf, *tvp;
  
  for (;;) {
    r= internal_check(ads,query_io,answer_r,context_r);
    if (r != EWOULDBLOCK) return r;
    maxfd= 0; tvp= 0;
    FD_ZERO(&readfds); FD_ZERO(&writefds); FD_ZERO(&exceptfds);
    adns_interest(ads,&maxfd,&readfds,&writefds,&exceptfds,&tvp,&tvbuf);
    rsel= select(maxfd,&readfds,&writefds,&exceptfds,tvp);
    if (rsel==-1) {
      if (errno == EINTR && !(ads->iflags & adns_if_eintr)) continue;
      return errno;
    }
    rcb= adns_callback(ads,maxfd,&readfds,&writefds,&exceptfds);
    assert(rcb==rsel);
  }
}

int adns_check(adns_state ads,
	       adns_query *query_io,
	       adns_answer **answer_r,
	       void **context_r) {
  struct timeval now;
  int r;
  
  r= gettimeofday(&now,0); if (r) return errno;
  adns__autosys(ads,now);
  return internal_check(ads,query_io,answer_r,context_r);
}
