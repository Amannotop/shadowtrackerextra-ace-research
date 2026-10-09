// ax_receipt.c — receipt chain: selectors -> callers -> parse/validity -> outcome
#include "ax_receipt.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
static int has_raw(const ax_image_t *img, const char *s) {
  size_t nl = strlen(s), lim = img->img_len < 8000000 ? img->img_len : 8000000;
  for (size_t k = 0; k + nl < lim; k++)
    if (!memcmp(img->img + k, s, nl)) return 1;
  return 0;
}
int ax_receipt_analyze(const ax_image_t *img, const char *app_dir, ax_db_t *db) {
  int n = 0;
  int hasURL = has_raw(img, "appStoreReceiptURL");
  int hasAtt = has_raw(img, "attestKey");
  int hasProv = has_raw(img, "mobileprovision");
  int hasReceipt = has_raw(img, "receipt");
  char scinfo[1024];
  snprintf(scinfo, sizeof(scinfo), "%s/SC_Info", app_dir);
  struct stat st;
  int hasSC = !stat(scinfo, &st);
  char ev[640];
  snprintf(ev, sizeof(ev),
    "binary: appStoreReceiptURL=%d attestKey=%d mobileprovision-ref=%d receipt-ref=%d | bundle: SC_Info=%d "
    "(chain: receipt-URL -> absence/parse/validity branches -> outcome values; attest challenge/callback/failure; provision discrimination)",
    hasURL, hasAtt, hasProv, hasReceipt, hasSC);
  ax_conf_t c = AX_LOW;
  int signals = (hasURL > 0) + (hasAtt > 0) + (hasSC > 0);
  if (signals >= 3) c = AX_HIGH;
  else if (signals == 2) c = AX_MED;
  ax_db_add(db, AXCAT_RECEIPT, c, "receipt", "chain: receipt/attest/provision", ev, 0, signals);
  n++;
  if (hasAtt) {
    ax_db_add(db, AXCAT_SIG, AX_MED, "receipt", "attest challenge path",
      "attestKey:clientDataHash:completionHandler: present — map challenge format + response builder + failure branch (response forgery lives/dies here)", 0, 2);
    n++;
  }
  if (!hasSC) {
    ax_db_add(db, AXCAT_RECEIPT, AX_MED, "receipt", "SC_Info absent?",
      "no SC_Info dir in bundle — receipt-file checks must fail-open or fail-closed: find the branch (absence handling decides ban-vs-pass on sideload)", 0, 2);
    n++;
  }
  return n;
}
