#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef int (*JNI_OnLoad_t)(void*, void*);
typedef int (*add_numbers_t)(int, int, int, int, int, int, int, int);
typedef int (*check_logic_t)(int, int, int, int, int, int, int, int);

int main() {
    printf("[Loader] Opening virtualized shared library: ./libprotected.so...\n");
    void *handle = dlopen("./libprotected.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "[Loader] dlopen failed: %s\n", dlerror());
        return 1;
    }
    printf("[Loader] Shared library loaded successfully!\n");

    // 1. Simulate JVM calling JNI_OnLoad
    JNI_OnLoad_t JNI_OnLoad = (JNI_OnLoad_t)dlsym(handle, "JNI_OnLoad");
    if (!JNI_OnLoad) {
        fprintf(stderr, "[Loader] Failed to find symbol 'JNI_OnLoad': %s\n", dlerror());
        dlclose(handle);
        return 1;
    }
    printf("[Loader] Simulating JVM calling JNI_OnLoad...\n");
    int jni_version = JNI_OnLoad(NULL, NULL);
    printf("[Loader] JNI_OnLoad returned version code: 0x%X\n", jni_version);
    if (jni_version != 0x00010006) {
        fprintf(stderr, "[Loader] ERROR: Unexpected JNI version 0x%X\n", jni_version);
        dlclose(handle);
        return 1;
    }

    // 2. Resolve and call add_numbers
    add_numbers_t add_numbers = (add_numbers_t)dlsym(handle, "add_numbers");
    if (!add_numbers) {
        fprintf(stderr, "[Loader] Failed to find symbol 'add_numbers': %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    // Call virtualized add_numbers(20, 30)
    int res_add = add_numbers(20, 30, 0, 0, 0, 0, 0, 0);
    printf("[Loader] add_numbers(20, 30) returned: %d\n", res_add);
    if (res_add != 50) {
        fprintf(stderr, "[Loader] ERROR: Expected 50, got %d\n", res_add);
        dlclose(handle);
        return 1;
    }

    // 3. Resolve and call check_logic
    check_logic_t check_logic = (check_logic_t)dlsym(handle, "check_logic");
    if (!check_logic) {
        fprintf(stderr, "[Loader] Failed to find symbol 'check_logic': %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    // check_logic(15) -> 15 > 10, should return 15 * 2 = 30
    int res_logic1 = check_logic(15, 0, 0, 0, 0, 0, 0, 0);
    printf("[Loader] check_logic(15) returned: %d\n", res_logic1);
    if (res_logic1 != 30) {
        fprintf(stderr, "[Loader] ERROR: Expected 30, got %d\n", res_logic1);
        dlclose(handle);
        return 1;
    }

    // check_logic(4) -> 4 <= 10, should return 4 - 5 = -1
    int res_logic2 = check_logic(4, 0, 0, 0, 0, 0, 0, 0);
    printf("[Loader] check_logic(4) returned: %d\n", res_logic2);
    if (res_logic2 != -1) {
        fprintf(stderr, "[Loader] ERROR: Expected -1, got %d\n", res_logic2);
        dlclose(handle);
        return 1;
    }

    printf("[Loader] All assertions passed! The virtualized .so works flawlessly under the custom VM.\n");
    dlclose(handle);
    return 0;
}
