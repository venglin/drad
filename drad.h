/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * Copyright (C) 2010 Przemyslaw Frasunek <venglin@freebsd.lublin.pl>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include <arpa/inet.h>

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

/* configuration values */

#define	CTL_BACKLOG	                10                      /* maximum number of unaccepted control connections */
#define CTL_PORT	                5007                    /* listen port for control connections */
#define MAXIFACES	                2048                    /* maximum number of interfaces */
#define MAXCLIENTS	                128                     /* maximum number of simultaneous control connections */
#define TIMEOUT		                2                       /* event loop timeout (seconds) */
#define RA_UPD_TIMEOUT	            60                      /* how often send unsolicited RAs on enabled interfaces (seconds) */
#define CTL_TIMEOUT                 10                      /* timeout for control command input */
#define HOPLIM		                64                      /* advertised hop limit */
#define LIFETIME	                1800                    /* advertised router lifetime */
#define PREFIX_LEN                  64                      /* advertised prefix length */
#define VALID_TIME                  2592000                 /* advertised prefix validity time */
#define PREF_TIME                   604800                  /* advertised prefix preferred time */

/* constants */

#define ALLROUTERS_LINK	            "ff02::2"
#define ALLNODES	                "ff02::1"
#define LINEBUFSZ	                1024

/* states for control connections */

#define ST_IDLE		                0
#define ST_ACCEPT	                1
#define ST_READ		                2
#define ST_PROCESS	                4
#define ST_WANTMORE	                8
#define ST_CLOSE	                16
#define ST_ERROR	                32

/* debug macros */

#define WHERESTR                    "[file %s, line %d]: "
#define WHEREARG                    __FILE__, __LINE__
#define DEBUG_PRINT(...)            syslog(LOG_DEBUG, __VA_ARGS__)
#define debug_printf(_fmt, ...)	    DEBUG_PRINT(WHERESTR _fmt, WHEREARG, __VA_ARGS__)

/* command response macros */

#define OK_STR                      "+OK\n"
#define ERR_STR                     "-ERR\n"
#define OK(x)			            write(x, OK_STR, sizeof(OK_STR) - 1)
#define ERR(x)			            write(x, ERR_STR, sizeof(ERR_STR) - 1)

/* data structures */

typedef struct _client_t {
	int fd;
	int state;
	char linebuf[LINEBUFSZ];
	int linepos;
	int accepttime;
} client_t;

typedef struct _iface_t {
	int up;
	int errors;
	struct in6_addr global;
	char name[16];
} iface_t;

/* function prototypes */

int ctrl_sock_open(void);
int icmp_sock_open(void);
int init_events(int csock);
int fill(client_t *client, int remaining);
int disable(int argc, char **argv, int fd);
int enable(int argc, char **argv, int fd);
int add_global(int argc, char **argv, int fd);
int process(client_t *client);
int rs_input(int len, struct nd_router_solicit *rs, struct in6_pktinfo *pi, struct sockaddr_in6 *from);
int ra_output(int ifindex);
int icmp_input(void);
