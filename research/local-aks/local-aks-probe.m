// Local AppleKeyStore capability probe for Mirra research.
// Read-only by default. --test-keybag creates and immediately unloads one
// isolated, in-memory keybag; never touches system keybags or credentials.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <string.h>
#include <unistd.h>

typedef int (*CreateBag)(const void *, int, int, int *);
typedef int (*UnloadBag)(int);

static NSArray<NSString *> *symbols(void) {
    return @[
        @"aks_create_bag", @"aks_unload_bag",
        @"aks_create_signing_key", @"aks_create_signing_key_with_params",
        @"aks_sign_signing_key", @"aks_params_create", @"aks_params_set_data",
        @"aks_params_set_number", @"aks_params_get_der",
        @"aks_remote_session", @"aks_remote_session_step",
        @"aks_remote_session_reset", @"aks_remote_session_token",
        @"aks_remote_peer_confirm", @"aks_remote_peer_setup",
        @"aks_validate_local_key", @"aks_remote_peer_get_state",
        @"aks_remote_peer_drop"
    ];
}

static void emit(NSDictionary *value) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:value
        options:NSJSONWritingPrettyPrinted error:nil];
    if (data) { fwrite(data.bytes, 1, data.length, stdout); putchar('\n'); }
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        BOOL testBag = argc == 2 && strcmp(argv[1], "--test-keybag") == 0;
        if (argc != 1 && !testBag) {
            fprintf(stderr, "Usage: local-aks-probe [--test-keybag]\n");
            return 2;
        }
        const char *path =
            "/System/Library/PrivateFrameworks/AppleKeyStore.framework/Versions/A/AppleKeyStore";
        void *library = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
        NSMutableArray *found = [NSMutableArray array], *missing = [NSMutableArray array];
        for (NSString *name in symbols()) {
            if (library && dlsym(library, name.UTF8String)) [found addObject:name];
            else [missing addObject:name];
        }
        NSMutableDictionary *report = [@{
            @"probe": @"local-aks",
            @"mode": testBag ? @"isolated_keybag_test" : @"symbols_only",
            @"framework_loaded": @(library != NULL),
            @"symbols_found": found,
            @"symbols_missing": missing,
            @"all_required_symbols_found": @(missing.count == 0),
            @"hardware_attestation_verified": @NO,
            @"mirroring_verified": @NO,
            @"note": @"Symbol availability does not prove SEP, T2, DCRT or remote-session support."
        } mutableCopy];
        if (!testBag) { emit(report); if (library) dlclose(library); return library ? 0 : 1; }
        CreateBag create = library ? (CreateBag)dlsym(library, "aks_create_bag") : NULL;
        UnloadBag unload = library ? (UnloadBag)dlsym(library, "aks_unload_bag") : NULL;
        if (!create || !unload) {
            report[@"keybag_test"] = @{@"error": @"keybag_symbols_unavailable"};
            emit(report);
            if (library) dlclose(library);
            return 1;
        }
        uint8_t secret[32] = {0};
        if (SecRandomCopyBytes(kSecRandomDefault, sizeof(secret), secret) != errSecSuccess) {
            report[@"keybag_test"] = @{@"error": @"random_generation_failed"};
            emit(report); dlclose(library); return 1;
        }
        int bag = -1;
        int createStatus = create(secret, (int)sizeof(secret), 0, &bag);
        explicit_bzero(secret, sizeof(secret));
        int unloadStatus = -1;
        if (createStatus == 0 && bag >= 0) unloadStatus = unload(bag);
        // Never expose a native keybag handle in the report.
        report[@"keybag_test"] = @{
            @"create_status": @(createStatus),
            @"unload_status": @(unloadStatus),
            @"created": @(createStatus == 0 && bag >= 0),
            @"unloaded": @(createStatus == 0 && bag >= 0 && unloadStatus == 0)
        };
        emit(report);
        dlclose(library);
        return createStatus == 0 && unloadStatus == 0 ? 0 : 1;
    }
}
