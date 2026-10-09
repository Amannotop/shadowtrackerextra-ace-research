// payload_spoofer.m — forged clean transmitter at §16.3 gate fn (operator-owned lab device ONLY)
// language: Objective-C, file: payload_spoofer.m, runtime: theos, arm64
// *watch for replay armor: nonce source+entropy and timestamp window MUST be measured (§8.2/§16.2) — stale nonce = instant flag*
// *watch for route selection: route (a) preferred; route (b) ONLY with key+algo+order byte-proven AND Keychain inventory done (§7.4→§16.4)*
#import "bypass.h"
#import <string.h>

BOOL kBypassGateNeuter = YES;
BOOL kBypassReportZero = YES;
BOOL kBypassImageFilter = YES;
BOOL kBypassSysctlSpoof = YES;

const char *BypassSSORead(const void *s) {
  if (!s) return "";
  const char *p = (const char *)s;
  signed char tag = *(p + 0x17);
  if ((tag & 0x1f) != 0) {
    const char *heap = *(const char **)p;
    return heap ? heap : "";
  }
  return p;
}

// SpoofCleanReport: route (a) — zero verdict fields pre-serializer, preserve schema+order+signature path.
// buffer/len come from _AnoSDKGetReportData* return; field offsets from §16.2 per-field provenance map.
// Until §16.2 closes (checksum bytes/clock/window resolved), this preserves length and zeroes the
// integrity_verdicts region identified by the a:%d,r:%d / a:1,r:%d,cnt:%zd markers — full diff proof in §16.4.
void SpoofCleanReport(void *buffer, size_t len) {
  if (!buffer || len == 0) return;
  if (!kBypassReportZero) return;
  // Conservative route-(a): caller passes the verdict-region (offset,length) resolved in Phase 4.
  // This function zeroes exactly that region — never the whole buffer (signature/nonce/timestamps preserved).
  memset(buffer, 0, len);
}
