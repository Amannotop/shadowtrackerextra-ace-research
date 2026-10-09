// ax_codesign.h — signature/entitlement/provisioning/bundle differential evidence (SentinelForge)
// Operates on the APP BUNDLE directory (not just the binary): Info.plist, embedded.mobileprovision,
// _CodeSignature/CodeResources, sideload artifacts. Produces env-A vs env-B comparable rows.
#ifndef AX_CODESIGN_H
#define AX_CODESIGN_H
#include "ax_common.h"
// app_dir = ".../ShadowTrackerExtra.app". Fills findings; returns count.
int ax_codesign_analyze(const char *app_dir, const char *main_binary_path, ax_db_t *db);
#endif
