
#include <stdio.h>
#include <dlfcn.h>
int main() {
    printf("Calling dlopen...\n");
    void* handle = dlopen("liblog.so", RTLD_GLOBAL | RTLD_LAZY);
    printf("dlopen returned: %p\n", handle);
    return 0;
}
