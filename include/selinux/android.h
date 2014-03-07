#ifndef _SELINUX_ANDROID_H_
#define _SELINUX_ANDROID_H_

#include <sys/types.h>
#include <unistd.h>

#include <selinux/label.h>

#ifdef __cplusplus
extern "C" {
#endif

extern struct selabel_handle* selinux_android_file_context_handle(void);

extern void selinux_android_set_sehandle(const struct selabel_handle *hndl);

extern int selinux_android_load_policy(void);

extern int selinux_android_reload_policy(void);

extern int selinux_android_setcontext(uid_t uid,
				      int isSystemServer,
				      const char *seinfo,
				      const char *name);

extern int selinux_android_setfilecon(const char *pkgdir,
				      const char *pkgname,
				      uid_t uid);

extern int selinux_android_setfilecon2(const char *pkgdir,
				       const char *pkgname,
				       const char *seinfo,
				       uid_t uid);

#define SELINUX_ANDROID_RESTORECON_NOCHANGE 1
#define SELINUX_ANDROID_RESTORECON_VERBOSE  2
#define SELINUX_ANDROID_RESTORECON_RECURSE  4
#define SELINUX_ANDROID_RESTORECON_FORCE    8
extern int selinux_android_restorecon_flags(const char *file, unsigned int flags);

#define selinux_android_restorecon(file,flags) selinux_android_restorecon_flags(file, flags)
#define selinux_android_restorecon(f) selinux_android_restorecon_flags(f, 0)
#define selinux_android_restorecon_recursive(f) selinux_android_restorecon_flags(f, SELINUX_ANDROID_RESTORECON_RECURSE)

extern int selinux_android_seapp_context_reload(void);

#ifdef __cplusplus
}
#endif
#endif
