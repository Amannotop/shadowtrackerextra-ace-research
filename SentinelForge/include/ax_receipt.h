// ax_receipt.h — receipt/provision/entitlement verification analysis (SentinelForge)
#ifndef AX_RECEIPT_H
#define AX_RECEIPT_H
#include "ax_macho.h"
// Cross-links binary evidence (appStoreReceiptURL/attestKey selectors, receipt strings)
// with bundle evidence (SC_Info, provision). Emits chain findings.
int ax_receipt_analyze(const ax_image_t *img, const char *app_dir, ax_db_t *db);
#endif
