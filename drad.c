/*
 * Copyright (C) 2010 Przemyslaw Frasunek <venglin@freebsd.lublin.pl>
 *
 * Parts derived from rtadvd:
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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


#include "drad.h"

static int isock = -1;
struct sockaddr_in6 rcvfrom;
struct msghdr rcvmhdr, sndmhdr;
static u_char *rcvcmsgbuf = NULL, *sndcmsgbuf = NULL;
static size_t rcvcmsgbuflen = 0, sndcmsgbuflen = 0;
iface_t ifaces[MAXIFACES];

int ctrl_sock_open(void) {
	int sock = -1;
	int val = 0;
	struct sockaddr_in temp;

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		debug_printf("socket failed (%s)\n", strerror(errno));
		return -1;
	}

	val = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	temp.sin_family = AF_INET;
	temp.sin_addr.s_addr = htonl(0x7f000001);
	temp.sin_port = htons(CTL_PORT);

	if (bind(sock, (struct sockaddr *)&temp, sizeof(temp))) {
		debug_printf("bind failed (%s)\n", strerror(errno));
		close(sock);
		return -1;
	}

	if (listen(sock, CTL_BACKLOG)) {
		debug_printf("listen failed (%s)\n", strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

int icmp_sock_open(void) {
	struct icmp6_filter filt;
	int val = 0;
	int sock = -1;
	static u_char answer[1500];
	static struct iovec rcviov[2], sndiov[2];

	rcvcmsgbuflen = CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int));
	if ((rcvcmsgbuf = (u_char *)malloc(rcvcmsgbuflen)) == NULL) {
		debug_printf("malloc failed (%s)\n", strerror(errno));
		return -1;
	}

	sndcmsgbuflen = CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int));
	if ((sndcmsgbuf = (u_char *)malloc(sndcmsgbuflen)) == NULL) {
		debug_printf("malloc failed (%s)\n", strerror(errno));
		return -1;
	}

	if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		debug_printf("socket failed (%s)\n", strerror(errno));
		return -1;
	}

	val = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val)) < 0) {
		debug_printf("setsockopt(IPV6_RECVPKTINFO) failed (%s)\n", strerror(errno));
		return -1;
	}

	val = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val, sizeof(val)) < 0) {
		debug_printf("setsockopt(IPV6_RECVHOPLIMIT) failed (%s)\n", strerror(errno));
		return -1;
	}

	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);

	if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) < 0) {
		debug_printf("setsockopt(ICMP6_FILTER) failed (%s)\n", strerror(errno));
		return -1;
	}

	rcviov[0].iov_base = (caddr_t)answer;
	rcviov[0].iov_len = sizeof(answer);
	rcvmhdr.msg_name = (caddr_t)&rcvfrom;
	rcvmhdr.msg_namelen = sizeof(rcvfrom);
	rcvmhdr.msg_iov = rcviov;
	rcvmhdr.msg_iovlen = 1;
	rcvmhdr.msg_control = (caddr_t) rcvcmsgbuf;

	sndmhdr.msg_namelen = sizeof(struct sockaddr_in6);
	sndmhdr.msg_iov = sndiov;
	sndmhdr.msg_iovlen = 1;
	sndmhdr.msg_control = (caddr_t)sndcmsgbuf;
	sndmhdr.msg_controllen = sndcmsgbuflen;

	return sock;
}

int init_events(int csock) {
	int queue = -1;
	struct kevent kev;

	if ((queue = kqueue()) < 0) {
		debug_printf("kqueue failed (%s)\n", strerror(errno));
		return -1;
	}

	memset(&kev, 0, sizeof(kev));
	EV_SET(&kev, isock, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(queue, &kev, 1, NULL, 0, NULL) < 0) {
		debug_printf("kevent failed (%s)\n", strerror(errno));
		return -1;
	}

	memset(&kev, 0, sizeof(kev));
	EV_SET(&kev, csock, EVFILT_READ, EV_ADD, 0, CTL_BACKLOG, NULL);

	if (kevent(queue, &kev, 1, NULL, 0, NULL) < 0) {
		debug_printf("kevent failed (%s)\n", strerror(errno));
		return -1;
	}

	return queue;
}
	
int fill(client_t *client, int remaining) {
	int rd;
	char *bufp;

	bufp = client->linebuf + client->linepos;

	if (remaining > LINEBUFSZ - client->linepos)
		return -1;

	if ((rd = read(client->fd, bufp, remaining)) < 0)
		return -1;

	client->linepos += rd;
	return rd;
}

int disable(int argc, char **argv, int fd) {
	unsigned int ifindex = 0;

	if (argc < 2) {
		ERR(fd);
		return -1;
	}

	if ((ifindex = if_nametoindex(argv[1])) == 0 || ifindex >= MAXIFACES) {
		ERR(fd);
		return -1;
	}

	memset(&ifaces[ifindex], 0, sizeof(ifaces[ifindex]));

	debug_printf("disable called for interface %s (%d)\n", argv[1], ifindex);

	OK(fd);
	return 0;
}

int enable(int argc, char **argv, int fd) {
	struct ipv6_mreq mreq;
	unsigned int ifindex = 0;

	if (argc < 2) {
		ERR(fd);
		return -1;
	}

	if ((ifindex = if_nametoindex(argv[1])) == 0 || ifindex >= MAXIFACES) {
		ERR(fd);
		return -1;
	}

    if (ifaces[ifindex].up >= 2) {
        /* trying to configure already running interface - disable it */
        memset(&ifaces[ifindex], 0, sizeof(ifaces[ifindex]));
    }

	inet_pton(AF_INET6, ALLROUTERS_LINK, &mreq.ipv6mr_multiaddr.s6_addr);
	mreq.ipv6mr_interface = ifindex;
	if (setsockopt(isock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
		debug_printf("setsockopt(IPV6_JOIN_GROUP) failed (%s)\n", strerror(errno));

	ifaces[ifindex].up++;
	strlcpy(ifaces[ifindex].name, argv[1], sizeof(ifaces[ifindex].name));

	debug_printf("enable called for interface %s (%d)\n", argv[1], ifindex);

	OK(fd);
	return 0;
}

int list(int argc, char **argv, int fd) {
	int i;
	char linebuf[LINEBUFSZ];
	char ntopbuf[INET6_ADDRSTRLEN];
    char tmp[20];

    snprintf(linebuf, sizeof(linebuf),
        "+------------------+----------------------------------+-----------+--------+\n"
        "| Interface        | IPv6 Prefix                      | State (*) | Errors |\n"
        "+------------------+----------------------------------+-----------+--------+\n");
    write(fd, linebuf, strlen(linebuf));

	for (i = 0; i < MAXIFACES; i++) {
		if (ifaces[i].up) {
            snprintf(tmp, sizeof(tmp), "%s (%d)", ifaces[i].name, i);
			snprintf(linebuf, sizeof(linebuf), 
                "| %-16s | %-32s | %9d | %6d |\n", tmp, inet_ntop(AF_INET6, &ifaces[i].global, ntopbuf, INET6_ADDRSTRLEN), 
                ifaces[i].up, ifaces[i].errors);
			write(fd, linebuf, strlen(linebuf));
		}
	}

    snprintf(linebuf, sizeof(linebuf),
        "+------------------+----------------------------------+-----------+--------+\n");
    write(fd, linebuf, strlen(linebuf));
    snprintf(linebuf, sizeof(linebuf), "(*) - Possible states: 1 - configured, 2 - up and sending RAs\n");
    write(fd, linebuf, strlen(linebuf));

    OK(fd);

	return 0;
}

int add_global(int argc, char **argv, int fd) {
	unsigned int ifindex = 0;

	if (argc < 3) {
		ERR(fd);
		return -1;
	}

	debug_printf("add %s on %s\n", argv[2], argv[1]);

	if ((ifindex = if_nametoindex(argv[1])) == 0) {
		ERR(fd);
		return -1;
	}

    if (ifaces[ifindex].up >= 2) {
        /* trying to configure already running interface - disable it */
        memset(&ifaces[ifindex], 0, sizeof(ifaces[ifindex]));
    }

	if (inet_pton(AF_INET6, argv[2], &ifaces[ifindex].global) != 1) {
		ERR(fd);
		return -1;
	}

	strlcpy(ifaces[ifindex].name, argv[1], sizeof(ifaces[ifindex].name));
    ifaces[ifindex].up++;

	OK(fd);

	return 0;
}


int process(client_t *client) {
	int argc, i, escaped, j, matched;
	char **argv, *p, *q;
	struct cmds *cmdp;
	int fd = client->fd;

	struct cmds {
		char *cmd;
		int (*func)(int, char **, int);
	} cmdtab[] = {
		{ "enable", enable },
		{ "disable", disable },
		{ "global", add_global },
		{ "list", list },
		{ NULL, NULL }
	};

	if ((p = rindex(client->linebuf, '\r')) != NULL)
		*p = '\0';
	if ((p = rindex(client->linebuf, '\n')) != NULL)
		*p = '\0';

	for (p = client->linebuf; *p && (*p == ' ' || *p == '\t'); p++);
	q = p;

	for (i = 0, escaped = 0; *p; p++) {
		if (*p == '"' && *(p-1) != '\\')
			escaped = ~escaped;

		if (*p == ' ' && !escaped) {
			*p = '\0';
			i++;
		}
	}

	argc = i + 1;
	j = 0;

	argv = (char **)malloc((argc + 1) * sizeof(char *));
	for (j = 0; j < argc; j++) {
		p = argv[j] = (char *)malloc(strlen(q) + 1);
		while(*q) {
			if (*q == '"') {
				if (*(q+1))
					q++;
				else
					break;
			}

			if (*q == '\\' && (*(q+1) == '"' || *(q+1) == '\\'))
				q++;

			*p++ = *q++;
		}

		*p = '\0';
		q++;
	}

	argv[argc] = '\0';

	for (matched = 0, cmdp = cmdtab; cmdp->cmd; cmdp++) {
		if(!strcasecmp(argv[0], (const char *)cmdp->cmd)) {
			matched = 1;
			(*cmdp->func)(argc, argv, fd);
		}
	}

	if (!matched)
		ERR(fd);

	for(i = 0; i < argc; i++)
		free((void *)argv[i]);

	free((void *)argv);

	return 0;
}

int rs_input(int len, struct nd_router_solicit *rs, struct in6_pktinfo *pi, struct sockaddr_in6 *from) {
	char ntopbuf[INET6_ADDRSTRLEN];
	const char *pntopbuf;
	unsigned int ifindex = pi->ipi6_ifindex;

	pntopbuf = inet_ntop(AF_INET6, &from->sin6_addr, ntopbuf, INET6_ADDRSTRLEN);

	debug_printf("RS received from %s on %d\n", pntopbuf, ifindex);
	if (ifaces[ifindex].up > 1 && ifaces[ifindex].errors < 10)
		ra_output(ifindex);

	return 0;
}

int ra_output(int ifindex) {
	char ntopbuf[INET6_ADDRSTRLEN];
	struct sockaddr_in6 sin6_allnodes = {sizeof(sin6_allnodes), AF_INET6};
	size_t packlen;
	char *buf, *bufp;
	struct nd_router_advert *ra;
	struct cmsghdr *cm;
	struct in6_pktinfo *pi;
	struct nd_opt_prefix_info *ndopt_pi;

	packlen = sizeof(struct nd_router_advert) + sizeof(struct nd_opt_prefix_info);
	if ((buf = malloc(packlen)) == NULL) {
		debug_printf("malloc failed (%s)\n", strerror(errno));
		return -1;
	}

	bufp = buf;

	ra = (struct nd_router_advert *)buf;
	ra->nd_ra_type = ND_ROUTER_ADVERT;
	ra->nd_ra_code = 0;
	ra->nd_ra_cksum = 0;
	ra->nd_ra_curhoplimit = (u_int8_t)(0xff & HOPLIM);
	ra->nd_ra_flags_reserved = 0;
	ra->nd_ra_router_lifetime = htons(LIFETIME);
	ra->nd_ra_reachable = htonl(0);
	ra->nd_ra_retransmit = htonl(0);
	bufp += sizeof(*ra);

	ndopt_pi = (struct nd_opt_prefix_info *)bufp;
	ndopt_pi->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	ndopt_pi->nd_opt_pi_len = 4;
	ndopt_pi->nd_opt_pi_prefix_len = PREFIX_LEN;
	ndopt_pi->nd_opt_pi_flags_reserved = 0;
	ndopt_pi->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
	ndopt_pi->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
	ndopt_pi->nd_opt_pi_valid_time = htonl(VALID_TIME);
	ndopt_pi->nd_opt_pi_preferred_time = htonl(PREF_TIME);
	ndopt_pi->nd_opt_pi_reserved2 = 0;
	ndopt_pi->nd_opt_pi_prefix = ifaces[ifindex].global;
	bufp += sizeof(struct nd_opt_prefix_info);

	inet_pton(AF_INET6, ALLNODES, &sin6_allnodes.sin6_addr);

	sndmhdr.msg_name = (caddr_t)&sin6_allnodes;
	sndmhdr.msg_iov[0].iov_base = (caddr_t)buf;
	sndmhdr.msg_iov[0].iov_len = packlen;

	cm = CMSG_FIRSTHDR(&sndmhdr);
	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_PKTINFO;
	cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	pi = (struct in6_pktinfo *)CMSG_DATA(cm);
	memset(&pi->ipi6_addr, 0, sizeof(pi->ipi6_addr)); 
	pi->ipi6_ifindex = ifindex;

	{
		int hoplimit = 255;

		cm = CMSG_NXTHDR(&sndmhdr, cm);
		cm->cmsg_level = IPPROTO_IPV6;
		cm->cmsg_type = IPV6_HOPLIMIT;
		cm->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cm), &hoplimit, sizeof(int));
	}

	debug_printf("offering %s on %d\n", inet_ntop(AF_INET6, &ifaces[ifindex].global, ntopbuf, INET6_ADDRSTRLEN), ifindex);

	if (sendmsg(isock, &sndmhdr, 0) < 0) {
		ifaces[ifindex].errors++;
		debug_printf("sendmsg failed on %d (%s)\n", ifindex, strerror(errno));
		return -1;
	}

	free(buf);

	return 0;
}

int icmp_input(void) {
	int i;
	int *hlimp = NULL;
	struct icmp6_hdr *icp;
	int ifindex = 0;
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	struct in6_addr dst = in6addr_any;

	rcvmhdr.msg_controllen = rcvcmsgbuflen;

	if ((i = recvmsg(isock, &rcvmhdr, 0)) < 0)
		return -1;

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&rcvmhdr);
	  cm;
	  cm = (struct cmsghdr *)CMSG_NXTHDR(&rcvmhdr, cm)) {
		 if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO && cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
			ifindex = pi->ipi6_ifindex;
			dst = pi->ipi6_addr;
		}

		if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_HOPLIMIT && cm->cmsg_len == CMSG_LEN(sizeof(int)))
			hlimp = (int *)CMSG_DATA(cm);
	}

	if (ifindex == 0) {
		debug_printf("no ifindex on incoming packet from %d", isock);
		return -1;
	}

	if (hlimp == NULL) {
		debug_printf("no hoplimit on incoming packet from %d", ifindex);
		return -1;
	}

	if (ifaces[ifindex].up == 0) {
		debug_printf("discarding packet for unconfigured interface %d\n", ifindex);
		return -1;
	}

	if (i < sizeof(struct icmp6_hdr)) {
		debug_printf("message from %d is too short (%d < %d)\n", ifindex, i, sizeof(struct icmp6_hdr));
		return -1;
	}

	icp = (struct icmp6_hdr *)rcvmhdr.msg_iov[0].iov_base;

	switch (icp->icmp6_type) {
		case ND_ROUTER_SOLICIT:
			if (*hlimp != 255) {
				debug_printf("RS with invalid hop limit (%d) received on %d\n", *hlimp, ifindex);
				return -1;
			}

			if (icp->icmp6_code) {
				debug_printf("RS with invalid code (%d) received on %d\n", icp->icmp6_code, ifindex);
				return -1;
			}

			if (i < sizeof(struct nd_router_solicit)) {
				debug_printf("RS too short (%d < %d) received on %d\n", i, sizeof(struct nd_router_solicit), ifindex);
				return -1;
			}

			rs_input(i, (struct nd_router_solicit *)icp, pi, &rcvfrom);
			break;
	}

	return 0;
}

int main(int argc, char **argv) {
	int csock = -1, queue = -1;
	client_t clients[MAXCLIENTS], *client;
	struct timespec timeout;
	int last_check, last_ra_updates, t0, i, clisock, remaining;
	struct kevent kev;
	struct sockaddr_in temp;
	size_t len;

	daemon(0, 0);
        openlog("drad", LOG_PID, LOG_DAEMON);

	if ((isock = icmp_sock_open()) < 0) {
		return -1;
	}

	if ((csock = ctrl_sock_open()) < 0) {
		if (isock > 0)
			close(isock);
		return -1;
	}

	if ((queue = init_events(csock)) < 0) {
		if (isock > 0)
			close(isock);
		if (csock > 0)
			close(csock);
	}

	memset(clients, 0, sizeof(clients));
	memset(ifaces, 0, sizeof(ifaces));
	timeout.tv_sec = TIMEOUT;
	timeout.tv_nsec = 0;
	last_ra_updates = last_check = time(NULL);

	for(;;) {
		t0 = time(NULL);
		if (t0 - last_check > CTL_TIMEOUT) {
			for (i = 0; i < MAXCLIENTS; i++) {
				if (clients[i].state != ST_IDLE) {
					if (t0 - clients[i].accepttime > CTL_TIMEOUT) {
						debug_printf("fd = %d timedout\n", i);
						clients[i].state = ST_IDLE;
						close(i);
					}
				}
				last_check = t0;
			}
		}

		if (t0 - last_ra_updates > RA_UPD_TIMEOUT) {
			for(i = 0; i < MAXIFACES; i++) {
				if (ifaces[i].up > 1 && ifaces[i].errors < 10)
					ra_output(i);
			}

			last_ra_updates = t0;
		}

		if ((i = kevent(queue, NULL, 0, &kev, 1, &timeout)) < 0) {
			debug_printf("kevent wait failed (%s)\n", strerror(errno));
			sleep(10);
			continue;
		}

		if (i == 0)
			continue; /* it's only timeout */

		if (kev.ident == csock) {
			/* incoming connection on control socket */
			len = sizeof(struct sockaddr_in);
			if ((clisock = accept(csock, (struct sockaddr *)&temp, &len)) < 0) {
				debug_printf("accept failed (%s)\n", strerror(errno));
				continue;
			}

			if (clisock >= MAXCLIENTS) {
				debug_printf("too large client fd (%d), dropping\n", clisock);
				close(clisock);
				continue;
			}

			clients[clisock].fd = clisock;
			clients[clisock].state = ST_ACCEPT;
			clients[clisock].accepttime = time(NULL);
			clients[clisock].linebuf[0] = 0;
			clients[clisock].linepos = 0;
			
			memset(&kev, 0, sizeof(kev));
			EV_SET(&kev, clisock, EVFILT_READ, EV_ADD, 0, 0, NULL);
			
			if (kevent(queue, &kev, 1, 0, 0, NULL) < 0) {
				debug_printf("kevent add failed (%s)\n", strerror(errno));
			}

			debug_printf("control connection accepted, fd = %d\n", clisock);

			continue;
		}

		if (kev.ident == isock) {
			/* incoming icmpv6 packet */
			icmp_input();
			continue;
		}

		debug_printf("event from fd = %d\n", kev.ident);

		if (kev.ident >= MAXCLIENTS)
			continue;

		clisock = kev.ident;
		remaining = kev.data;
		client = &clients[clisock];

		if (remaining == 0)
			client->state = ST_CLOSE;

restart:
		switch(client->state) {
			case ST_IDLE:
				debug_printf("leaving with ST_IDLE for fd = %d\n", client->fd);
				break;

			case ST_CLOSE:
				close(client->fd);
				client->state = ST_IDLE;
				goto restart;

			case ST_WANTMORE:
				client->state = ST_ACCEPT;
				break;

			case ST_ACCEPT:
				if (fill(client, remaining) < 0)
					client->state = ST_ERROR;
				client->state = ST_READ;
				goto restart;

			case ST_READ:
				if (client->linepos < 2) {
					if (client->linebuf[client->linepos - 1] == '\n')
						client->state = ST_ERROR;
					else
						client->state = ST_WANTMORE;
					goto restart;
				}

				client->state = ST_PROCESS;

				goto restart;

			case ST_PROCESS:
				process(client);
				client->state = ST_CLOSE;
				goto restart;

			case ST_ERROR:
				ERR(client->fd);
				client->state = ST_CLOSE;
				goto restart;
		}
	}

	return 0;
}
