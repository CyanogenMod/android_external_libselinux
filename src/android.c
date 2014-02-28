#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <fts.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/avc.h>
#include <mincrypt/sha.h>
#include <private/android_filesystem_config.h>
#include "policy.h"
#include "callbacks.h"
#include "selinux_internal.h"

/*
 * XXX Where should this configuration file be located?
 * Needs to be accessible by zygote and installd when
 * setting credentials for app processes and setting permissions
 * on app data directories.
 */
static char const * const seapp_contexts_file[] = {
	"/seapp_contexts",
	NULL };

static const struct selinux_opt seopts[] = {
	{ SELABEL_OPT_PATH, "/file_contexts" },
	{ 0, NULL } };

static const char *const sepolicy_file[] = {
        "/sepolicy",
        NULL };

enum levelFrom {
	LEVELFROM_NONE,
	LEVELFROM_APP,
	LEVELFROM_USER,
	LEVELFROM_ALL
};

#if DEBUG
static char const * const levelFromName[] = {
	"none",
	"app",
	"user",
	"all"
};
#endif

struct prefix_str {
	size_t len;
	char *str;
	char is_prefix;
};

struct seapp_context {
	/* input selectors */
	char isSystemServer;
	struct prefix_str user;
	char *seinfo;
	struct prefix_str name;
	struct prefix_str path;
	/* outputs */
	char *domain;
	char *type;
	char *level;
	char *sebool;
	enum levelFrom levelFrom;
};

static int seapp_context_cmp(const void *A, const void *B)
{
	const struct seapp_context *const *sp1 = (const struct seapp_context *const *) A;
	const struct seapp_context *const *sp2 = (const struct seapp_context *const *) B;
	const struct seapp_context *s1 = *sp1, *s2 = *sp2;

	/* Give precedence to isSystemServer=true. */
	if (s1->isSystemServer != s2->isSystemServer)
		return (s1->isSystemServer ? -1 : 1);

	/* Give precedence to a specified user= over an unspecified user=. */
	if (s1->user.str && !s2->user.str)
		return -1;
	if (!s1->user.str && s2->user.str)
		return 1;

	if (s1->user.str) {
		/* Give precedence to a fixed user= string over a prefix. */
		if (s1->user.is_prefix != s2->user.is_prefix)
			return (s2->user.is_prefix ? -1 : 1);

		/* Give precedence to a longer prefix over a shorter prefix. */
		if (s1->user.is_prefix && s1->user.len != s2->user.len)
			return (s1->user.len > s2->user.len) ? -1 : 1;
	}

	/* Give precedence to a specified seinfo= over an unspecified seinfo=. */
	if (s1->seinfo && !s2->seinfo)
		return -1;
	if (!s1->seinfo && s2->seinfo)
		return 1;

	/* Give precedence to a specified name= over an unspecified name=. */
	if (s1->name.str && !s2->name.str)
		return -1;
	if (!s1->name.str && s2->name.str)
		return 1;

	if (s1->name.str) {
		/* Give precedence to a fixed name= string over a prefix. */
		if (s1->name.is_prefix != s2->name.is_prefix)
			return (s2->name.is_prefix ? -1 : 1);

		/* Give precedence to a longer prefix over a shorter prefix. */
		if (s1->name.is_prefix && s1->name.len != s2->name.len)
			return (s1->name.len > s2->name.len) ? -1 : 1;
	}

	/* Give precedence to a specified path= over an unspecified path=. */
	if (s1->path.str && !s2->path.str)
		return -1;
	if (!s1->path.str && s2->path.str)
		return 1;

	if (s1->path.str) {
		/* Give precedence to a fixed path= string over a prefix. */
		if (s1->path.is_prefix != s2->path.is_prefix)
			return (s2->path.is_prefix ? -1 : 1);

		/* Give precedence to a longer prefix over a shorter prefix. */
		if (s1->path.is_prefix && s1->path.len != s2->path.len)
			return (s1->path.len > s2->path.len) ? -1 : 1;
	}

        /* Give precedence to a specified sebool= over an unspecified sebool=. */
        if (s1->sebool && !s2->sebool)
                return -1;
        if (!s1->sebool && s2->sebool)
                return 1;

	/* Anything else has equal precedence. */
	return 0;
}

static struct seapp_context **seapp_contexts = NULL;
static int nspec = 0;

int selinux_android_seapp_context_reload(void)
{
	FILE *fp = NULL;
	char line_buf[BUFSIZ];
	char *token;
	unsigned lineno;
	struct seapp_context *cur;
	char *p, *name = NULL, *value = NULL, *saveptr;
	size_t len;
	int i = 0, n, ret;

	while ((fp==NULL) && seapp_contexts_file[i])
		fp = fopen(seapp_contexts_file[i++], "r");

	if (!fp) {
		selinux_log(SELINUX_ERROR, "%s:  could not open any seapp_contexts file", __FUNCTION__);
		return -1;
	}

	if (seapp_contexts) {
		for (n = 0; n < nspec; n++) {
			cur = seapp_contexts[n];
			free(cur->user.str);
			free(cur->seinfo);
			free(cur->name.str);
			free(cur->path.str);
			free(cur->domain);
			free(cur->type);
			free(cur->level);
			free(cur->sebool);
		}
		free(seapp_contexts);
	}

	nspec = 0;
	while (fgets(line_buf, sizeof line_buf - 1, fp)) {
		p = line_buf;
		while (isspace(*p))
			p++;
		if (*p == '#' || *p == 0)
			continue;
		nspec++;
	}

	seapp_contexts = (struct seapp_context **) calloc(nspec, sizeof(struct seapp_context *));
	if (!seapp_contexts)
		goto oom;

	rewind(fp);
	nspec = 0;
	lineno = 1;
	while (fgets(line_buf, sizeof line_buf - 1, fp)) {
		len = strlen(line_buf);
		if (line_buf[len - 1] == '\n')
			line_buf[len - 1] = 0;
		p = line_buf;
		while (isspace(*p))
			p++;
		if (*p == '#' || *p == 0)
			continue;

		cur = (struct seapp_context *) calloc(1, sizeof(struct seapp_context));
		if (!cur)
			goto oom;

		token = strtok_r(p, " \t", &saveptr);
		if (!token)
			goto err;

		while (1) {
			name = token;
			value = strchr(name, '=');
			if (!value)
				goto err;
			*value++ = 0;

			if (!strcasecmp(name, "isSystemServer")) {
				if (!strcasecmp(value, "true"))
					cur->isSystemServer = 1;
				else if (!strcasecmp(value, "false"))
					cur->isSystemServer = 0;
				else {
					goto err;
				}
			} else if (!strcasecmp(name, "user")) {
				cur->user.str = strdup(value);
				if (!cur->user.str)
					goto oom;
				cur->user.len = strlen(cur->user.str);
				if (cur->user.str[cur->user.len-1] == '*')
					cur->user.is_prefix = 1;
			} else if (!strcasecmp(name, "seinfo")) {
				cur->seinfo = strdup(value);
				if (!cur->seinfo)
					goto oom;
			} else if (!strcasecmp(name, "name")) {
				cur->name.str = strdup(value);
				if (!cur->name.str)
					goto oom;
				cur->name.len = strlen(cur->name.str);
				if (cur->name.str[cur->name.len-1] == '*')
					cur->name.is_prefix = 1;
			} else if (!strcasecmp(name, "domain")) {
				cur->domain = strdup(value);
				if (!cur->domain)
					goto oom;
			} else if (!strcasecmp(name, "type")) {
				cur->type = strdup(value);
				if (!cur->type)
					goto oom;
			} else if (!strcasecmp(name, "levelFromUid")) {
				if (!strcasecmp(value, "true"))
					cur->levelFrom = LEVELFROM_APP;
				else if (!strcasecmp(value, "false"))
					cur->levelFrom = LEVELFROM_NONE;
				else {
					goto err;
				}
			} else if (!strcasecmp(name, "levelFrom")) {
				if (!strcasecmp(value, "none"))
					cur->levelFrom = LEVELFROM_NONE;
				else if (!strcasecmp(value, "app"))
					cur->levelFrom = LEVELFROM_APP;
				else if (!strcasecmp(value, "user"))
					cur->levelFrom = LEVELFROM_USER;
				else if (!strcasecmp(value, "all"))
					cur->levelFrom = LEVELFROM_ALL;
				else {
					goto err;
				}
			} else if (!strcasecmp(name, "level")) {
				cur->level = strdup(value);
				if (!cur->level)
					goto oom;
			} else if (!strcasecmp(name, "path")) {
				cur->path.str = strdup(value);
				if (!cur->path.str)
					goto oom;
				cur->path.len = strlen(cur->path.str);
				if (cur->path.str[cur->path.len-1] == '*')
					cur->path.is_prefix = 1;
			} else if (!strcasecmp(name, "sebool")) {
				cur->sebool = strdup(value);
				if (!cur->sebool)
					goto oom;
			} else
				goto err;

			token = strtok_r(NULL, " \t", &saveptr);
			if (!token)
				break;
		}

		seapp_contexts[nspec] = cur;
		nspec++;
		lineno++;
	}

	qsort(seapp_contexts, nspec, sizeof(struct seapp_context *),
	      seapp_context_cmp);

#if DEBUG
	{
		int i;
		for (i = 0; i < nspec; i++) {
			cur = seapp_contexts[i];
			selinux_log(SELINUX_INFO, "%s:  isSystemServer=%s user=%s seinfo=%s name=%s path=%s sebool=%s -> domain=%s type=%s level=%s levelFrom=%s",
			__FUNCTION__,
			cur->isSystemServer ? "true" : "false", cur->user.str,
			cur->seinfo, cur->name.str, cur->path.str, cur->sebool, cur->domain,
			cur->type, cur->level,
			levelFromName[cur->levelFrom]);
		}
	}
#endif

	ret = 0;

out:
	fclose(fp);
	return ret;

err:
	selinux_log(SELINUX_ERROR, "%s:  Error reading %s, line %u, name %s, value %s\n",
		    __FUNCTION__, seapp_contexts_file[i - 1], lineno, name, value);
	ret = -1;
	goto out;
oom:
	selinux_log(SELINUX_ERROR, 
		    "%s:  Out of memory\n", __FUNCTION__);
	ret = -1;
	goto out;
}


static void seapp_context_init(void)
{
        selinux_android_seapp_context_reload();
}

static pthread_once_t once = PTHREAD_ONCE_INIT;

/*
 * Max id that can be mapped to category set uniquely
 * using the current scheme.
 */
#define CAT_MAPPING_MAX_ID (0x1<<16)

enum seapp_kind {
	SEAPP_TYPE,
	SEAPP_DOMAIN
};

static int seapp_context_lookup(enum seapp_kind kind,
				uid_t uid,
				int isSystemServer,
				const char *seinfo,
				const char *pkgname,
				const char *path,
				context_t ctx)
{
	const char *username = NULL;
	struct seapp_context *cur = NULL;
	int i;
	size_t n;
	uid_t userid;
	uid_t appid;

	__selinux_once(once, seapp_context_init);

	userid = uid / AID_USER;
	appid = uid % AID_USER;
	if (appid < AID_APP) {
		for (n = 0; n < android_id_count; n++) {
			if (android_ids[n].aid == appid) {
				username = android_ids[n].name;
				break;
			}
		}
		if (!username)
			goto err;
	} else if (appid < AID_ISOLATED_START) {
		username = "_app";
		appid -= AID_APP;
	} else {
		username = "_isolated";
		appid -= AID_ISOLATED_START;
	}

	if (appid >= CAT_MAPPING_MAX_ID || userid >= CAT_MAPPING_MAX_ID)
		goto err;

	for (i = 0; i < nspec; i++) {
		cur = seapp_contexts[i];

		if (cur->isSystemServer != isSystemServer)
			continue;

		if (cur->user.str) {
			if (cur->user.is_prefix) {
				if (strncasecmp(username, cur->user.str, cur->user.len-1))
					continue;
			} else {
				if (strcasecmp(username, cur->user.str))
					continue;
			}
		}

		if (cur->seinfo) {
			if (!seinfo || strcasecmp(seinfo, cur->seinfo))
				continue;
		}

		if (cur->name.str) {
			if(!pkgname)
				continue;

			if (cur->name.is_prefix) {
				if (strncasecmp(pkgname, cur->name.str, cur->name.len-1))
					continue;
			} else {
				if (strcasecmp(pkgname, cur->name.str))
					continue;
			}
		}

		if (cur->path.str) {
			if (!path)
				continue;

			if (cur->path.is_prefix) {
				if (strncmp(path, cur->path.str, cur->path.len-1))
					continue;
			} else {
				if (strcmp(path, cur->path.str))
					continue;
			}
		}

		if (kind == SEAPP_TYPE && !cur->type)
			continue;
		else if (kind == SEAPP_DOMAIN && !cur->domain)
			continue;

		if (cur->sebool) {
			int value = security_get_boolean_active(cur->sebool);
			if (value == 0)
				continue;
			else if (value == -1) {
				selinux_log(SELINUX_ERROR, \
				"Could not find boolean: %s ", cur->sebool);
				goto err;
			}
		}

		if (kind == SEAPP_TYPE) {
			if (context_type_set(ctx, cur->type))
				goto oom;
		} else if (kind == SEAPP_DOMAIN) {
			if (context_type_set(ctx, cur->domain))
				goto oom;
		}

		if (cur->levelFrom != LEVELFROM_NONE) {
			char level[255];
			switch (cur->levelFrom) {
			case LEVELFROM_APP:
				snprintf(level, sizeof level, "s0:c%u,c%u",
					 appid & 0xff,
					 256 + (appid>>8 & 0xff));
				break;
			case LEVELFROM_USER:
				snprintf(level, sizeof level, "s0:c%u,c%u",
					 512 + (userid & 0xff),
					 768 + (userid>>8 & 0xff));
				break;
			case LEVELFROM_ALL:
				snprintf(level, sizeof level, "s0:c%u,c%u,c%u,c%u",
					 appid & 0xff,
					 256 + (appid>>8 & 0xff),
					 512 + (userid & 0xff),
					 768 + (userid>>8 & 0xff));
				break;
			default:
				goto err;
			}
			if (context_range_set(ctx, level))
				goto oom;
		} else if (cur->level) {
			if (context_range_set(ctx, cur->level))
				goto oom;
		}

		break;
	}

	if (kind == SEAPP_DOMAIN && i == nspec) {
		/*
		 * No match.
		 * Fail to prevent staying in the zygote's context.
		 */
		selinux_log(SELINUX_ERROR,
			    "%s:  No match for app with uid %d, seinfo %s, name %s\n",
			    __FUNCTION__, uid, seinfo, pkgname);

		if (security_getenforce() == 1)
			goto err;
	}

	return 0;
err:
	return -1;
oom:
	return -2;
}

int selinux_android_setfilecon(const char *pkgdir,
				const char *pkgname,
				const char *seinfo,
				uid_t uid)
{
	char *orig_ctx_str = NULL;
	char *ctx_str = NULL;
	context_t ctx = NULL;
	int rc = -1;

	if (is_selinux_enabled() <= 0)
		return 0;

	rc = getfilecon(pkgdir, &ctx_str);
	if (rc < 0)
		goto err;

	ctx = context_new(ctx_str);
	orig_ctx_str = ctx_str;
	if (!ctx)
		goto oom;

	rc = seapp_context_lookup(SEAPP_TYPE, uid, 0, seinfo, pkgname, NULL, ctx);
	if (rc == -1)
		goto err;
	else if (rc == -2)
		goto oom;

	ctx_str = context_str(ctx);
	if (!ctx_str)
		goto oom;

	rc = security_check_context(ctx_str);
	if (rc < 0)
		goto err;

	if (strcmp(ctx_str, orig_ctx_str)) {
		rc = setfilecon(pkgdir, ctx_str);
		if (rc < 0)
			goto err;
	}

	rc = 0;
out:
	freecon(orig_ctx_str);
	context_free(ctx);
	return rc;
err:
	selinux_log(SELINUX_ERROR, "%s:  Error setting context for pkgdir %s, uid %d: %s\n",
		    __FUNCTION__, pkgdir, uid, strerror(errno));
	rc = -1;
	goto out;
oom:
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __FUNCTION__);
	rc = -1;
	goto out;
}

int selinux_android_setcontext(uid_t uid,
			       int isSystemServer,
			       const char *seinfo,
			       const char *pkgname)
{
	char *orig_ctx_str = NULL, *ctx_str;
	context_t ctx = NULL;
	int rc = -1;

	if (is_selinux_enabled() <= 0)
		return 0;

	rc = getcon(&ctx_str);
	if (rc)
		goto err;

	ctx = context_new(ctx_str);
	orig_ctx_str = ctx_str;
	if (!ctx)
		goto oom;

	rc = seapp_context_lookup(SEAPP_DOMAIN, uid, isSystemServer, seinfo, pkgname, NULL, ctx);
	if (rc == -1)
		goto err;
	else if (rc == -2)
		goto oom;

	ctx_str = context_str(ctx);
	if (!ctx_str)
		goto oom;

	rc = security_check_context(ctx_str);
	if (rc < 0)
		goto err;

	if (strcmp(ctx_str, orig_ctx_str)) {
		rc = setcon(ctx_str);
		if (rc < 0)
			goto err;
	}

	rc = 0;
out:
	freecon(orig_ctx_str);
	context_free(ctx);
	avc_netlink_close();
	return rc;
err:
	if (isSystemServer)
		selinux_log(SELINUX_ERROR,
				"%s:  Error setting context for system server: %s\n",
				__FUNCTION__, strerror(errno));
	else 
		selinux_log(SELINUX_ERROR,
				"%s:  Error setting context for app with uid %d, seinfo %s: %s\n",
				__FUNCTION__, uid, seinfo, strerror(errno));

	rc = -1;
	goto out;
oom:
	selinux_log(SELINUX_ERROR, "%s:  Out of memory\n", __FUNCTION__);
	rc = -1;
	goto out;
}

static struct selabel_handle *sehandle = NULL;
#define FC_DIGEST_SIZE SHA_DIGEST_SIZE
static uint8_t fc_digest[FC_DIGEST_SIZE];

static struct selabel_handle *get_selabel_handle(const struct selinux_opt opts[])
{
    struct selabel_handle *h;
    unsigned int i = 0;
    int fd;
    struct stat sb;
    void *map;

    h = NULL;
    while ((h == NULL) && opts[i].value) {
        h = selabel_open(SELABEL_CTX_FILE, &opts[i], 1);
        if (h)
            break;
        i++;
    }

    if (!h)
        return NULL;

    fd = open(opts[i].value, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        selinux_log(SELINUX_ERROR, "SELinux:  Could not open %s:  %s\n",
                    opts[i].value, strerror(errno));
        goto err;
    }
    if (fstat(fd, &sb) < 0) {
        selinux_log(SELINUX_ERROR, "SELinux:  Could not stat %s:  %s\n",
                    opts[i].value, strerror(errno));
        close(fd);
        goto err;
    }
    map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        selinux_log(SELINUX_ERROR, "SELinux:  Could not map %s:  %s\n",
                    opts[i].value, strerror(errno));
        close(fd);
        goto err;
    }
    SHA_hash(map, sb.st_size, fc_digest);
    munmap(map, sb.st_size);
    close(fd);

    selinux_log(SELINUX_INFO, "SELinux: Loaded file_contexts from %s\n",
                opts[i].value);

    return h;

err:
    selabel_close(h);
    return NULL;
}

static struct selabel_handle *file_context_open(void)
{
	struct selabel_handle *h;

	h = get_selabel_handle(seopts);

	if (!h)
		selinux_log(SELINUX_ERROR, "%s: Error getting file context handle (%s)\n",
				__FUNCTION__, strerror(errno));
	return h;
}

static void file_context_init(void)
{
    if (!sehandle)
        sehandle = file_context_open();
}

static pthread_once_t fc_once = PTHREAD_ONCE_INIT;

struct pkgInfo {
    char *name;
    uid_t uid;
    bool debuggable;
    char *dataDir;
    char *seinfo;
    struct pkgInfo *next;
};

#define PKGTAB_SIZE 256
static struct pkgInfo *pkgTab[PKGTAB_SIZE];

static unsigned int pkghash(const char *pkgname)
{
    unsigned int h = 7;
    for (; *pkgname; pkgname++) {
        h = h * 31 + *pkgname;
    }
    return h & (PKGTAB_SIZE - 1);
}

/* The file containing the list of installed packages on the system */
#define PACKAGES_LIST_FILE  "/data/system/packages.list"

static void package_info_init(void)
{
    char *buf = NULL;
    size_t buflen = 0;
    ssize_t bytesread;
    FILE *fp;
    char *cur, *next;
    struct pkgInfo *pkgInfo = NULL;
    unsigned int hash;
    unsigned long lineno = 1;

    fp = fopen(PACKAGES_LIST_FILE, "r");
    if (!fp) {
        selinux_log(SELINUX_ERROR, "SELinux:  Could not open %s:  %s.\n",
                    PACKAGES_LIST_FILE, strerror(errno));
        return;
    }
    while ((bytesread = getline(&buf, &buflen, fp)) > 0) {
        pkgInfo = calloc(1, sizeof(*pkgInfo));
        if (!pkgInfo)
            goto err;
        next = buf;
        cur = strsep(&next, " \t\n");
        if (!cur)
            goto err;
        pkgInfo->name = strdup(cur);
        if (!pkgInfo->name)
            goto err;
        cur = strsep(&next, " \t\n");
        if (!cur)
            goto err;
        pkgInfo->uid = atoi(cur);
        if (!pkgInfo->uid)
            goto err;
        cur = strsep(&next, " \t\n");
        if (!cur)
            goto err;
        pkgInfo->debuggable = atoi(cur);
        cur = strsep(&next, " \t\n");
        if (!cur)
            goto err;
        pkgInfo->dataDir = strdup(cur);
        if (!pkgInfo->dataDir)
            goto err;
        cur = strsep(&next, " \t\n");
        if (!cur)
            goto err;
        pkgInfo->seinfo = strdup(cur);
        if (!pkgInfo->seinfo)
            goto err;

        hash = pkghash(pkgInfo->name);
        if (pkgTab[hash])
            pkgInfo->next = pkgTab[hash];
        pkgTab[hash] = pkgInfo;

        lineno++;
    }

#if DEBUG
    {
        unsigned int buckets, entries, chainlen, longestchain;

        buckets = entries = longestchain = 0;
        for (hash = 0; hash < PKGTAB_SIZE; hash++) {
            if (pkgTab[hash]) {
                buckets++;
                chainlen = 0;
                for (pkgInfo = pkgTab[hash]; pkgInfo; pkgInfo = pkgInfo->next) {
                    chainlen++;
                    selinux_log(SELINUX_INFO, "%s:  name=%s uid=%u debuggable=%s dataDir=%s seinfo=%s\n",
                                __FUNCTION__,
                                pkgInfo->name, pkgInfo->uid, pkgInfo->debuggable ? "true" : "false", pkgInfo->dataDir, pkgInfo->seinfo);
                }
                entries += chainlen;
                if (longestchain < chainlen)
                    longestchain = chainlen;
            }
        }
        selinux_log(SELINUX_INFO, "SELinux:  %d pkg entries and %d/%d buckets used, longest chain %d\n", entries, buckets, PKGTAB_SIZE, longestchain);
    }
#endif

out:
    free(buf);
    fclose(fp);
    return;

err:
    selinux_log(SELINUX_ERROR, "SELinux:  Error reading %s on line %lu.\n",
                PACKAGES_LIST_FILE, lineno);
    if (pkgInfo) {
        free(pkgInfo->name);
        free(pkgInfo->dataDir);
        free(pkgInfo->seinfo);
        free(pkgInfo);
    }
    goto out;
}

static pthread_once_t pkg_once = PTHREAD_ONCE_INIT;

struct pkgInfo *package_info_lookup(const char *name)
{
    struct pkgInfo *pkgInfo;
    unsigned int hash;

    __selinux_once(pkg_once, package_info_init);

    hash = pkghash(name);
    for (pkgInfo = pkgTab[hash]; pkgInfo; pkgInfo = pkgInfo->next) {
        if (!strcmp(name, pkgInfo->name))
            return pkgInfo;
    }
    return NULL;
}

/* The path prefixes of package data directories. */
#define DATA_DATA_PATH "/data/data"
#define DATA_USER_PATH "/data/user"
#define DATA_DATA_PREFIX DATA_DATA_PATH "/"
#define DATA_USER_PREFIX DATA_USER_PATH "/"

static int pkgdir_selabel_lookup(const char *pathname, char **secontextp)
{
    char *pkgname = NULL, *end = NULL;
    struct pkgInfo *pkgInfo = NULL;
    char *secontext = *secontextp;
    context_t ctx = NULL;
    int rc = 0;

    /* Skip directory prefix before package name. */
    if (!strncmp(pathname, DATA_DATA_PREFIX, sizeof(DATA_DATA_PREFIX)-1)) {
        pathname += sizeof(DATA_DATA_PREFIX) - 1;
    } else if (!strncmp(pathname, DATA_USER_PREFIX, sizeof(DATA_USER_PREFIX)-1)) {
        pathname += sizeof(DATA_USER_PREFIX) - 1;
        while (isdigit(*pathname))
            pathname++;
        if (*pathname == '/')
            pathname++;
        else
            return 0;
    } else
        return 0;

    if (!(*pathname))
        return 0;

    pkgname = strdup(pathname);
    if (!pkgname)
        return -1;

    for (end = pkgname; *end && *end != '/'; end++)
        ;
    pathname = end;
    if (*end)
        pathname++;
    *end = '\0';

    pkgInfo = package_info_lookup(pkgname);
    if (!pkgInfo) {
        free(pkgname);
        return 0;
    }

    ctx = context_new(secontext);
    if (!ctx)
        goto err;

    rc = seapp_context_lookup(SEAPP_TYPE, pkgInfo->uid, 0,
                              pkgInfo->seinfo, pkgInfo->name, pathname, ctx);
    if (rc < 0)
        goto err;

    secontext = context_str(ctx);
    if (!secontext)
        goto err;

    if (!strcmp(secontext, *secontextp))
        goto out;

    rc = security_check_context(secontext);
    if (rc < 0)
        goto err;

    freecon(*secontextp);
    *secontextp = strdup(secontext);
    if (!(*secontextp))
        goto err;

    rc = 0;

out:
    free(pkgname);
    context_free(ctx);
    return rc;
err:
    selinux_log(SELINUX_ERROR, "%s:  Error looking up context for path %s, pkgname %s, seinfo %s, uid %u: %s\n",
                __FUNCTION__, pathname, pkgname, pkgInfo->seinfo, pkgInfo->uid, strerror(errno));
    rc = -1;
    goto out;
}

#define RESTORECON_LAST "security.restorecon_last"

static int restorecon_sb(const char *pathname, const struct stat *sb, bool setrestoreconlast, bool nochange, bool verbose)
{
    char *secontext = NULL;
    char *oldsecontext = NULL;
    int rc = 0;

    if (selabel_lookup(sehandle, &secontext, pathname, sb->st_mode) < 0)
        return -1;

    if (lgetfilecon(pathname, &oldsecontext) < 0)
        goto err;

    /*
     * Disable setting restorecon_last on /data/data or /data/user
     * since their labeling is based on seapp_contexts and seinfo
     * assignments rather than file_contexts and is managed by
     * installd rather than init.
     */
    if (!strcmp(pathname, DATA_DATA_PATH) || !strcmp(pathname, DATA_USER_PATH))
        setrestoreconlast = false;

    if (!strncmp(pathname, DATA_DATA_PREFIX, sizeof(DATA_DATA_PREFIX)-1) ||
        !strncmp(pathname, DATA_USER_PREFIX, sizeof(DATA_USER_PREFIX)-1)) {
        /* Same as above for all children of /data/data and /data/user. */
        setrestoreconlast = false;

        if (pkgdir_selabel_lookup(pathname, &secontext) < 0)
            goto err;
    }

    if (strcmp(oldsecontext, secontext) != 0) {
        if (verbose)
            selinux_log(SELINUX_INFO,
                        "SELinux:  Relabeling %s from %s to %s.\n", pathname, oldsecontext, secontext);
        if (!nochange) {
            if (lsetfilecon(pathname, secontext) < 0)
                goto err;
        }
    }

    if (setrestoreconlast && !nochange && S_ISDIR(sb->st_mode))
        setxattr(pathname, RESTORECON_LAST, fc_digest, sizeof fc_digest, 0);

    rc = 0;

out:
    freecon(oldsecontext);
    freecon(secontext);
    return rc;

err:
    selinux_log(SELINUX_ERROR,
                "SELinux: Could not set context for %s:  %s\n",
                pathname, strerror(errno));
    rc = -1;
    goto out;
}

int selinux_android_restorecon(const char* pathname, unsigned int flags)
{
    bool nochange = (flags & SELINUX_ANDROID_RESTORECON_NOCHANGE) ? true : false;
    bool verbose = (flags & SELINUX_ANDROID_RESTORECON_VERBOSE) ? true : false;
    bool recurse = (flags & SELINUX_ANDROID_RESTORECON_RECURSE) ? true : false;
    bool force = (flags & SELINUX_ANDROID_RESTORECON_FORCE) ? true : false;
    bool datadata = (flags & SELINUX_ANDROID_RESTORECON_DATADATA) ? true : false;
    struct stat sb;
    FTS *fts;
    FTSENT *ftsent;
    char *const paths[2] = { __UNCONST(pathname), NULL };
    int ftsflags = FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV | FTS_PHYSICAL;
    int error, sverrno;
    char xattr_value[FC_DIGEST_SIZE];
    ssize_t size;

    if (is_selinux_enabled() <= 0)
        return 0;

    __selinux_once(fc_once, file_context_init);

    if (!sehandle)
        return 0;

    if (!recurse) {
        if (lstat(pathname, &sb) < 0)
            return -1;

        return restorecon_sb(pathname, &sb, false, nochange, verbose);
    }

    /*
     * Ignore restorecon_last on /data/data or /data/user
     * since their labeling is based on seapp_contexts and seinfo
     * assignments rather than file_contexts and is managed by
     * installd rather than init.
     */
    if (!strcmp(pathname, DATA_DATA_PATH) || !strcmp(pathname, DATA_USER_PATH))
        force = true;

    size = getxattr(pathname, RESTORECON_LAST, xattr_value, sizeof fc_digest);
    if (!force && size == sizeof fc_digest && memcmp(fc_digest, xattr_value, sizeof fc_digest) == 0) {
        selinux_log(SELINUX_INFO,
                    "SELinux: Skipping restorecon_recursive(%s)\n",
                    pathname);
        return 0;
    }

    fts = fts_open(paths, ftsflags, NULL);
    if (!fts)
        return -1;

    error = 0;
    while ((ftsent = fts_read(fts)) != NULL) {
        switch (ftsent->fts_info) {
        case FTS_DC:
            selinux_log(SELINUX_ERROR,
                        "SELinux:  Directory cycle on %s.\n", ftsent->fts_path);
            errno = ELOOP;
            error = -1;
            goto out;
        case FTS_DP:
            continue;
        case FTS_DNR:
            selinux_log(SELINUX_ERROR,
                        "SELinux:  Could not read %s: %s.\n", ftsent->fts_path, strerror(errno));
            fts_set(fts, ftsent, FTS_SKIP);
            continue;
        case FTS_NS:
            selinux_log(SELINUX_ERROR,
                        "SELinux:  Could not stat %s: %s.\n", ftsent->fts_path, strerror(errno));
            fts_set(fts, ftsent, FTS_SKIP);
            continue;
        case FTS_ERR:
            selinux_log(SELINUX_ERROR,
                        "SELinux:  Error on %s: %s.\n", ftsent->fts_path, strerror(errno));
            fts_set(fts, ftsent, FTS_SKIP);
            continue;
        case FTS_D:
            if (!datadata &&
                (!strcmp(ftsent->fts_path, DATA_DATA_PATH) ||
                 !strcmp(ftsent->fts_path, DATA_USER_PATH))) {
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            }
            /* fall through */
        default:
            (void) restorecon_sb(ftsent->fts_path, ftsent->fts_statp, true, nochange, verbose);
            break;
        }
    }

out:
    sverrno = errno;
    (void) fts_close(fts);
    error = sverrno;
    return error;
}

struct selabel_handle* selinux_android_file_context_handle(void)
{
    return file_context_open();
}

void selinux_android_set_sehandle(const struct selabel_handle *hndl)
{
    sehandle = (struct selabel_handle *) hndl;
}

int selinux_android_reload_policy(void)
{
	int fd = -1, rc;
	struct stat sb;
	void *map = NULL;
	int i = 0;

	while (fd < 0 && sepolicy_file[i]) {
		fd = open(sepolicy_file[i], O_RDONLY | O_NOFOLLOW);
		i++;
	}
	if (fd < 0) {
		selinux_log(SELINUX_ERROR, "SELinux:  Could not open sepolicy:  %s\n",
				strerror(errno));
		return -1;
	}
	if (fstat(fd, &sb) < 0) {
		selinux_log(SELINUX_ERROR, "SELinux:  Could not stat %s:  %s\n",
				sepolicy_file[i-1], strerror(errno));
		close(fd);
		return -1;
	}
	map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		selinux_log(SELINUX_ERROR, "SELinux:  Could not map %s:  %s\n",
			sepolicy_file[i-1], strerror(errno));
		close(fd);
		return -1;
	}

	rc = security_load_policy(map, sb.st_size);
	if (rc < 0) {
		selinux_log(SELINUX_ERROR, "SELinux:  Could not load policy:  %s\n",
			strerror(errno));
		munmap(map, sb.st_size);
		close(fd);
		return -1;
	}

	munmap(map, sb.st_size);
	close(fd);
	selinux_log(SELINUX_INFO, "SELinux: Loaded policy from %s\n", sepolicy_file[i-1]);

	return 0;
}

int selinux_android_load_policy(void)
{
	const char *mnt = SELINUXMNT;
	int rc;
	rc = mount(SELINUXFS, mnt, SELINUXFS, 0, NULL);
	if (rc < 0) {
		if (errno == ENODEV) {
			/* SELinux not enabled in kernel */
			return -1;
		}
		if (errno == ENOENT) {
			/* Fall back to legacy mountpoint. */
			mnt = OLDSELINUXMNT;
			rc = mkdir(mnt, 0755);
			if (rc == -1 && errno != EEXIST) {
				selinux_log(SELINUX_ERROR,"SELinux:  Could not mkdir:  %s\n",
					strerror(errno));
				return -1;
			}
			rc = mount(SELINUXFS, mnt, SELINUXFS, 0, NULL);
		}
	}
	if (rc < 0) {
		selinux_log(SELINUX_ERROR,"SELinux:  Could not mount selinuxfs:  %s\n",
				strerror(errno));
		return -1;
	}
	set_selinuxmnt(mnt);

	return selinux_android_reload_policy();
}
