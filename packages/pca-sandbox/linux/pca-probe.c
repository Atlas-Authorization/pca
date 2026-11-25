/*
 * pca-probe: a tiny statically linked program that tries one thing and says whether the OS allowed it. The enforcement tests
 * run it under pca-confine. Prints `ok` or `err:<stage>:<errno>` and exits 0 either way.
 *
 *   pca-probe read PATH | write PATH | connect PORT | unixsock | ptrace | exec PATH
 *
 * Build: gcc -O2 -static -o pca-probe pca-probe.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void out(const char *s) { (void)!write(1, s, strlen(s)); (void)!write(1, "\n", 1); }
static void fail(const char *stage) { char b[64]; snprintf(b, sizeof b, "err:%s:%d", stage, errno); out(b); }

int main(int argc, char **argv) {
	if (argc < 2) { out("err:usage:0"); return 0; }
	const char *c = argv[1], *a = argc > 2 ? argv[2] : "";
	if (!strcmp(c, "read")) {
		int fd = open(a, O_RDONLY);
		if (fd < 0) { fail("open"); return 0; }
		char ch;
		if (read(fd, &ch, 1) < 0) { fail("read"); return 0; }
		out("ok");
	} else if (!strcmp(c, "write")) {
		int fd = open(a, O_WRONLY);
		if (fd < 0) { fail("open"); return 0; }
		if (write(fd, "x", 1) < 0) { fail("write"); return 0; }
		out("ok");
	} else if (!strcmp(c, "connect")) {
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) { fail("socket"); return 0; }
		struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((unsigned short)atoi(a)) };
		inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
		if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) { fail("connect"); return 0; }
		out("ok");
	} else if (!strcmp(c, "unixsock")) {
		int s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0) { fail("socket"); return 0; }
		out("ok");
	} else if (!strcmp(c, "ptrace")) {
		if (syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0) < 0) { fail("ptrace"); return 0; }
		out("ok");
	} else if (!strcmp(c, "exec")) {
		char *args[] = { (char *)a, NULL };
		execv(a, args);
		fail("exec");
	} else {
		out("err:usage:0");
	}
	return 0;
}
