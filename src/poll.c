/*
 * poll.c
 * - wrappers for poll(2)
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

#include <limits.h>

#include "internal.h"

#ifdef HAVE_POLL

int adns_beforepoll(adns_state ads, struct pollfd *fds, int *nfds_io, int *timeout_io,
		    const struct timeval *now) {
  struct timeval tv_nowbuf, tv_tobuf, *tv_to;
  int space, found, timeout_ms;
  struct pollfd fds_tmp[MAX_POLLFDS];

  if (timeout_io) {
    adns__must_gettimeofday(ads,&now,&tv_nowbuf);
    if (!now) { *nfds_io= 0; return 0; }

    timeout_ms= *timeout_io;
    if (timeout_ms == -1) {
      tv_to= 0;
    } else {
      tv_tobuf.tv_sec= timeout_ms / 1000;
      tv_tobuf.tv_usec= (timeout_ms % 1000)*1000;
      tv_to= &tv_tobuf;
    }

    adns__timeouts(ads, 0, &tv_to,&tv_tobuf, *now);

    if (tv_to) {
      assert(tv_to == &tv_tobuf);
      timeout_ms= (tv_tobuf.tv_usec+999)/1000;
      assert(tv_tobuf.tv_sec < (INT_MAX-timeout_ms)/1000);
      timeout_ms += tv_tobuf.tv_sec*1000;
    } else {
      timeout_ms= -1;
    }
    *timeout_io= timeout_ms;
  }
  
  space= *nfds_io;
  if (space >= MAX_POLLFDS) {
    found= adns__pollfds(ads,fds);
    *nfds_io= found;
  } else {
    found= adns__pollfds(ads,fds_tmp);
    *nfds_io= found;
    if (space < found) return ERANGE;
    memcpy(fds,fds_tmp,sizeof(struct pollfd)*found);
  }
  return 0;
}

void adns_afterpoll(adns_state ads, const struct pollfd *fds, int nfds,
		    const struct timeval *now) {
  struct timeval tv_buf;

  adns__must_gettimeofday(ads,&now,&tv_buf);
  if (!now) return;

  adns__timeouts(ads, 1, 0,0, *now);
  adns__fdevents(ads, fds,nfds, 0,0,0,0, *now,0);
}

#endif
