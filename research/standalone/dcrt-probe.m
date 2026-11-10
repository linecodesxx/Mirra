// Mirra standalone research: inspect the macOS MobileActivationMacOS DCRT API.
// Default: SYMBOLS ONLY. --copy-dcrt explicitly asks the system for a cached
// certificate but NEVER issues, writes, prints, or exports certificate bytes.
// This does not bypass Secure Enclave/T2 or change system settings.
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef NSData *(*CopyDCRT)(NSError *__autoreleasing *);

static void emit(NSDictionary *data) {
    NSData *json = [NSJSONSerialization dataWithJSONObject:data
        options:NSJSONWritingPrettyPrinted error:NULL];
    if (json) { fwrite(json.bytes, 1, json.length, stdout); putchar('\n'); }
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        BOOL copyRequested = argc == 2 && strcmp(argv[1], "--copy-dcrt") == 0;
        if (argc > 2 || (argc == 2 && !copyRequested)) {
            fprintf(stderr, "Usage: dcrt-probe [--copy-dcrt]\n");
            return 2;
        }
        const char *frameworks[] = {
            "/System/Library/PrivateFrameworks/MobileActivationMacOS.framework/Versions/A/MobileActivationMacOS",
            "/System/Library/PrivateFrameworks/MobileActivationMacOS.framework/MobileActivationMacOS"
        };
        void *library = NULL;
        for (size_t i = 0; i < sizeof(frameworks)/sizeof(frameworks[0]); ++i) {
            library = dlopen(frameworks[i], RTLD_LAZY | RTLD_LOCAL);
            if (library) break;
        }
        CopyDCRT copy = library ? (CopyDCRT)dlsym(library, "MAECopyDCRTMacOSWithError") : NULL;
        void *issue = library ? dlsym(library, "MAEIssueDCRTMacOSWithCallback") : NULL;
        NSMutableDictionary *report = [@{
            @"probe": @"local-dcrt",
            @"mode": copyRequested ? @"copy_cached_certificate" : @"symbols_only",
            @"framework_loaded": @(library != NULL),
            @"copy_symbol_found": @(copy != NULL),
            @"issue_symbol_found": @(issue != NULL),
            @"certificate_bytes_exported": @NO,
            @"certificate_issued": @NO,
            @"hardware_attestation_verified": @NO,
            @"mirroring_verified": @NO
        } mutableCopy];

        if (copyRequested) {
            if (!copy) {
                report[@"error"] = @"copy_symbol_unavailable";
            } else {
                NSError *error = nil;
                NSData *certificate = copy(&error);
                report[@"certificate_available"] = @([certificate isKindOfClass:NSData.class] && certificate.length > 0);
                report[@"certificate_size"] = @([certificate isKindOfClass:NSData.class] ? certificate.length : 0);
                if (error) {
                    report[@"error_domain"] = error.domain ?: @"";
                    report[@"error_code"] = @(error.code);
                }
                // Certificate bytes remain in system-managed memory only;
                // neither contents nor fingerprints are logged or persisted.
            }
        }
        emit(report);
        if (library) dlclose(library);
        return library && copy ? 0 : 1;
    }
}
