#ifndef _SELINUX_ANDROID_H_
#define _SELINUX_ANDROID_H_

#include <sys/types.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int selinux_android_setcontext(uid_t uid,
				      int isSystemServer,
				      const char *seinfo,
				      const char *name);

extern int selinux_android_setfilecon(const char *pkgdir,
				      const char *name,
				      uid_t uid);

extern int selinux_android_restorecon(const char *file);

extern int selinux_android_seapp_context_reload(void);

#ifdef __cplusplus
}
#endif
#endif
