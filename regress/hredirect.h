#ifndef HREDIRECT_H_INCLUDED
#define HREDIRECT_H_INCLUDED
#include "hsyscalls.h"
#undef select
#define select Hselect
#ifdef HAVE_POLL
#undef poll
#define poll Hpoll
#endif
#undef socket
#define socket Hsocket
#undef fcntl
#define fcntl Hfcntl
#undef connect
#define connect Hconnect
#undef close
#define close Hclose
#undef sendto
#define sendto Hsendto
#undef recvfrom
#define recvfrom Hrecvfrom
#undef read
#define read Hread
#undef write
#define write Hwrite
#undef int
#define writev Hwritev
#undef int
#define gettimeofday Hgettimeofday
#undef void*
#define malloc Hmalloc
#undef void
#define free Hfree
#undef void*
#define realloc Hrealloc
#undef void
#define exit Hexit
#endif
