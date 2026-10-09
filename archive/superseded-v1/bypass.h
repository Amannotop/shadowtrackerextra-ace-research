// bypass.h — shared tunables + prototypes for bypass.x / payload_spoofer.m
// language: Objective-C, file: bypass.h, runtime: theos, arm64
#ifndef BYPASS_H
#define BYPASS_H

#import <Foundation/Foundation.h>

// CONFIG tunables (defaults documented in bypass.x; override via NSUserDefaults lab-side only)
extern BOOL kBypassGateNeuter;
extern BOOL kBypassReportZero;
extern BOOL kBypassImageFilter;
extern BOOL kBypassSysctlSpoof;

// payload_spoofer entry: forged clean transmitter at §16.3 gate fn (route selection per §16.4 AFTER Keychain inventory)
void SpoofCleanReport(void *buffer, size_t len);

// SSO helper exposed for testing
const char *BypassSSORead(const void *s);

#endif
