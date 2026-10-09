// ax_environ.h — environment differential evidence (SentinelForge)
// Collects every observable that can differ between iOS-device (env A) and mac/sideload (env B):
// bundle, container, device-id APIs, loaded-module census hooks, env-var checks, proxy/reachability.
#ifndef AX_ENVIRON_H
#define AX_ENVIRON_H
#include "ax_macho.h"
int ax_environ_analyze(const ax_image_t *img, const char *app_dir, ax_db_t *db);
#endif
