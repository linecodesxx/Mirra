// Opt-in isolated signing-key test for a T2-less macOS host.
// Does not request DCRT attestation or access existing keybags.
// Neither generated key material nor native handles are printed.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef int (*CreateBag)(const void *, int, int, int *);
typedef int (*UnloadBag)(int);
typedef int (*CreateKey)(int, int, void **, size_t *);
typedef int (*ValidateKey)(int, int, const void *, size_t);

static void scrub(void *p, size_t n) {
    volatile uint8_t *bytes = (volatile uint8_t *)p;
    if (!bytes) return;
    for (size_t i = 0; i < n; ++i) bytes[i] = 0;
}
static void output(NSDictionary *object) {
    NSData *json = [NSJSONSerialization dataWithJSONObject:object
        options:NSJSONWritingPrettyPrinted error:nil];
    if (json) { fwrite(json.bytes, 1, json.length, stdout); putchar('\n'); }
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if ((argc != 2 && argc != 4) || strcmp(argv[1], "--test-signing-key") != 0 ||
            (argc == 4 && strcmp(argv[2], "--key-class") != 0)) {
            fprintf(stderr, "Usage: local-aks-key-probe --test-signing-key [--key-class 9|10|11]\n");
            return 2;
        }
        const char *path =
            "/System/Library/PrivateFrameworks/AppleKeyStore.framework/Versions/A/AppleKeyStore";
        void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        CreateBag createBag = lib ? (CreateBag)dlsym(lib, "aks_create_bag") : NULL;
        UnloadBag unloadBag = lib ? (UnloadBag)dlsym(lib, "aks_unload_bag") : NULL;
        CreateKey createKey = lib ? (CreateKey)dlsym(lib, "aks_create_signing_key") : NULL;
        ValidateKey validateKey = lib ? (ValidateKey)dlsym(lib, "aks_validate_local_key") : NULL;
        if (!createBag || !unloadBag || !createKey || !validateKey) {
            output(@{@"probe": @"local-aks-signing-key",
                     @"error": @"required_symbols_unavailable",
                     @"hardware_attestation_verified": @NO});
            if (lib) dlclose(lib);
            return 1;
        }

        uint8_t password[32];
        if (SecRandomCopyBytes(kSecRandomDefault, sizeof(password), password) != errSecSuccess) {
            output(@{@"probe": @"local-aks-signing-key",
                     @"error": @"secure_random_unavailable"});
            dlclose(lib);
            return 1;
        }

        int bag = -1;
        const int keyClass = argc == 4 ? atoi(argv[3]) : 9;
        if (keyClass != 9 && keyClass != 10 && keyClass != 11) {
            fprintf(stderr, "Invalid key class. Only 9, 10, 11 are accepted.\n");
            scrub(password, sizeof(password));
            dlclose(lib);
            return 2;
        }
        int bagStatus = createBag(password, (int)sizeof(password), 0, &bag);
        scrub(password, sizeof(password));

        int keyStatus = -1, validateStatus = -1, unloadStatus = -1;
        void *keyBlob = NULL;
        size_t blobSize = 0;
        BOOL keyCreated = NO;
        if (bagStatus == 0 && bag >= 0) {
            keyStatus = createKey(bag, keyClass, &keyBlob, &blobSize);
            keyCreated = (keyStatus == 0 && keyBlob != NULL && blobSize > 0 && blobSize <= 65536);
            if (keyCreated) {
                validateStatus = validateKey(bag, keyClass, keyBlob, blobSize);
            }
        }
        // AKS allocates the returned blob. Do not print or persist it.
        if (keyBlob) { scrub(keyBlob, blobSize); free(keyBlob); keyBlob = NULL; }
        if (bagStatus == 0 && bag >= 0) unloadStatus = unloadBag(bag);

        output(@{
            @"probe": @"local-aks-signing-key",
            @"key_class": @(keyClass),
            @"bag_create_status": @(bagStatus),
            @"signing_key_create_status": @(keyStatus),
            @"key_created": @(keyCreated),
            @"key_blob_size": @(keyCreated ? blobSize : 0),
            @"validate_status": @(validateStatus),
            @"bag_unload_status": @(unloadStatus),
            @"hardware_attestation_verified": @NO,
            @"mirroring_verified": @NO,
            @"note": @"Non-attested isolated test. A valid key does not prove SEP/DCRT support."
        });
        dlclose(lib);
        return (bagStatus == 0 && keyCreated && validateStatus == 0 && unloadStatus == 0) ? 0 : 1;
    }
}
