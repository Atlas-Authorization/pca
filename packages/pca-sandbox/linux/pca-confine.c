/*
 * pca-confine: apply a generated Landlock ruleset and seccomp filter to this process, then exec a command.
 *
 * Reference helper for the profiles @atlasauth/pca-sandbox generates (see confineArgs). It does not parse JSON: the package
 * flattens the profiles into flags.
 *
 *   pca-confine --landlock-abi
 *   pca-confine [--fs-handled A,B] [--fs PATH:A,B]... [--net-handled A,B] [--net PORT:A]...
 *               [--allow NAME]... [--allow-arg NAME:INDEX:VALUE]... -- COMMAND [ARGS...]
 *
 * A..B are Landlock access names without the LANDLOCK_ACCESS_ prefix (FS_READ_FILE, NET_CONNECT_TCP, ...). Without --allow
 * and --allow-arg no seccomp filter is installed. Exit codes: 70 Landlock unavailable, 71 Landlock too old for a requested
 * right, 72 other setup failure, 127 exec failed.
 *
 * Build: gcc -O2 -o pca-confine pca-confine.c -lseccomp
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags) { return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags); }
#endif
#ifndef landlock_add_rule
static inline int landlock_add_rule(int fd, enum landlock_rule_type type, const void *attr, uint32_t flags) { return (int)syscall(__NR_landlock_add_rule, fd, type, attr, flags); }
#endif
#ifndef landlock_restrict_self
static inline int landlock_restrict_self(int fd, uint32_t flags) { return (int)syscall(__NR_landlock_restrict_self, fd, flags); }
#endif

/* Access bits by name. Bits that a given ABI lacks are defined here so the table compiles against older headers. */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

struct acc { const char *name; uint64_t bit; int net; int abi; int dir_only; };
static const struct acc ACC[] = {
	{ "FS_EXECUTE", LANDLOCK_ACCESS_FS_EXECUTE, 0, 1, 0 },
	{ "FS_WRITE_FILE", LANDLOCK_ACCESS_FS_WRITE_FILE, 0, 1, 0 },
	{ "FS_READ_FILE", LANDLOCK_ACCESS_FS_READ_FILE, 0, 1, 0 },
	{ "FS_READ_DIR", LANDLOCK_ACCESS_FS_READ_DIR, 0, 1, 1 },
	{ "FS_REMOVE_DIR", LANDLOCK_ACCESS_FS_REMOVE_DIR, 0, 1, 1 },
	{ "FS_REMOVE_FILE", LANDLOCK_ACCESS_FS_REMOVE_FILE, 0, 1, 1 },
	{ "FS_MAKE_CHAR", LANDLOCK_ACCESS_FS_MAKE_CHAR, 0, 1, 1 },
	{ "FS_MAKE_DIR", LANDLOCK_ACCESS_FS_MAKE_DIR, 0, 1, 1 },
	{ "FS_MAKE_REG", LANDLOCK_ACCESS_FS_MAKE_REG, 0, 1, 1 },
	{ "FS_MAKE_SOCK", LANDLOCK_ACCESS_FS_MAKE_SOCK, 0, 1, 1 },
	{ "FS_MAKE_FIFO", LANDLOCK_ACCESS_FS_MAKE_FIFO, 0, 1, 1 },
	{ "FS_MAKE_BLOCK", LANDLOCK_ACCESS_FS_MAKE_BLOCK, 0, 1, 1 },
	{ "FS_MAKE_SYM", LANDLOCK_ACCESS_FS_MAKE_SYM, 0, 1, 1 },
	{ "FS_REFER", LANDLOCK_ACCESS_FS_REFER, 0, 2, 1 },
	{ "FS_TRUNCATE", LANDLOCK_ACCESS_FS_TRUNCATE, 0, 3, 0 },
	{ "NET_BIND_TCP", LANDLOCK_ACCESS_NET_BIND_TCP, 1, 4, 0 },
	{ "NET_CONNECT_TCP", LANDLOCK_ACCESS_NET_CONNECT_TCP, 1, 4, 0 },
};

static void die(int code, const char *what) {
	fprintf(stderr, "pca-confine: %s (errno %d)\n", what, errno);
	exit(code);
}

static const struct acc *find(const char *name) {
	for (size_t i = 0; i < sizeof ACC / sizeof ACC[0]; i++)
		if (strcmp(ACC[i].name, name) == 0) return &ACC[i];
	return NULL;
}

/* "A,B,C" -> bitmask of the given kind; a name the table does not know is fatal (never silently dropped). */
static uint64_t mask_of(const char *list, int net, int abi, int *needs_abi) {
	uint64_t m = 0;
	char *copy = strdup(list), *save = NULL;
	if (!copy) die(72, "out of memory");
	for (char *t = strtok_r(copy, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
		const struct acc *a = find(t);
		if (!a || a->net != net) { fprintf(stderr, "pca-confine: unknown access %s\n", t); exit(72); }
		if (a->abi > abi) { if (a->abi > *needs_abi) *needs_abi = a->abi; continue; }
		m |= a->bit;
	}
	free(copy);
	return m;
}

int main(int argc, char **argv) {
	if (argc == 2 && strcmp(argv[1], "--landlock-abi") == 0) {
		int v = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
		printf("%d\n", v < 0 ? 0 : v);
		return 0;
	}
	const char *fs_handled = NULL, *net_handled = NULL;
	const char *fs_rules[256], *net_rules[64], *allow[512], *allow_arg[64];
	int nfs = 0, nnet = 0, nallow = 0, nallow_arg = 0, i = 1;
	for (; i < argc && strcmp(argv[i], "--") != 0; i++) {
		const char *k = argv[i];
		if (i + 1 >= argc) die(72, "missing value");
		const char *v = argv[++i];
		if (!strcmp(k, "--fs-handled")) fs_handled = v;
		else if (!strcmp(k, "--net-handled")) net_handled = v;
		else if (!strcmp(k, "--fs") && nfs < 256) fs_rules[nfs++] = v;
		else if (!strcmp(k, "--net") && nnet < 64) net_rules[nnet++] = v;
		else if (!strcmp(k, "--allow") && nallow < 512) allow[nallow++] = v;
		else if (!strcmp(k, "--allow-arg") && nallow_arg < 64) allow_arg[nallow_arg++] = v;
		else die(72, "bad flag");
	}
	if (i >= argc || strcmp(argv[i], "--") != 0 || i + 1 >= argc) die(72, "no command");
	char **cmd = &argv[i + 1];

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) die(72, "no_new_privs");

	if (fs_handled || net_handled) {
		int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
		if (abi < 1) die(70, "landlock unavailable");
		int needs = 0;
		struct landlock_ruleset_attr attr = { 0 };
		if (fs_handled) attr.handled_access_fs = mask_of(fs_handled, 0, abi, &needs);
		if (net_handled) {
			uint64_t n = mask_of(net_handled, 1, abi, &needs);
			if (abi < 4) { fprintf(stderr, "pca-confine: network rules need Landlock ABI 4, have %d\n", abi); return 71; }
			attr.handled_access_net = n;
		}
		int rs = landlock_create_ruleset(&attr, sizeof attr, 0);
		if (rs < 0) die(72, "landlock_create_ruleset");
		for (int r = 0; r < nfs; r++) {
			char *spec = strdup(fs_rules[r]);
			char *colon = strrchr(spec, ':');
			if (!colon) die(72, "bad --fs");
			*colon = 0;
			int dummy = 0;
			uint64_t want = mask_of(colon + 1, 0, abi, &dummy) & attr.handled_access_fs;
			int fd = open(spec, O_PATH | O_CLOEXEC);
			if (fd < 0) die(72, spec);
			struct stat st;
			if (fstat(fd, &st)) die(72, "fstat");
			if (!S_ISDIR(st.st_mode)) {
				/* directory-only rights are invalid on a file rule */
				for (size_t a = 0; a < sizeof ACC / sizeof ACC[0]; a++) if (ACC[a].dir_only) want &= ~ACC[a].bit;
			}
			if (want == 0) { close(fd); free(spec); continue; }
			struct landlock_path_beneath_attr pb = { .allowed_access = want, .parent_fd = fd };
			if (landlock_add_rule(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0)) die(72, "landlock_add_rule fs");
			close(fd);
			free(spec);
		}
		for (int r = 0; r < nnet; r++) {
			char *spec = strdup(net_rules[r]);
			char *colon = strrchr(spec, ':');
			if (!colon) die(72, "bad --net");
			*colon = 0;
			int dummy = 0;
			struct landlock_net_port_attr np = { .allowed_access = mask_of(colon + 1, 1, abi, &dummy), .port = (uint64_t)atoi(spec) };
			if (landlock_add_rule(rs, LANDLOCK_RULE_NET_PORT, &np, 0)) die(72, "landlock_add_rule net");
			free(spec);
		}
		if (landlock_restrict_self(rs, 0)) die(72, "landlock_restrict_self");
		close(rs);
	}

	if (nallow || nallow_arg) {
		scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
		if (!ctx) die(72, "seccomp_init");
		for (int a = 0; a < nallow; a++) {
			int nr = seccomp_syscall_resolve_name(allow[a]);
			if (nr == __NR_SCMP_ERROR) continue; /* a name this architecture does not have */
			if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)) die(72, "seccomp_rule_add");
		}
		for (int a = 0; a < nallow_arg; a++) {
			char *spec = strdup(allow_arg[a]);
			char *c1 = strchr(spec, ':'), *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
			if (!c2) die(72, "bad --allow-arg");
			*c1 = 0; *c2 = 0;
			int nr = seccomp_syscall_resolve_name(spec);
			if (nr == __NR_SCMP_ERROR) continue;
			if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 1, SCMP_CMP((unsigned)atoi(c1 + 1), SCMP_CMP_EQ, (uint64_t)strtoull(c2 + 1, NULL, 10))))
				die(72, "seccomp_rule_add arg");
			free(spec);
		}
		if (seccomp_load(ctx)) die(72, "seccomp_load");
		seccomp_release(ctx);
	}

	execvp(cmd[0], cmd);
	die(127, "exec");
	return 127;
}
