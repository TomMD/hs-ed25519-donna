#ifndef ED25519_CUSTOM_RANDOM_BYTES
#define ED25519_CUSTOM_RANDOM_BYTES

#include <stdio.h>
#include <stdlib.h>

void ED25519_FN(ed25519_randombytes_unsafe)(void *p, size_t len)
{
    fprintf(stderr, "PANIC PANIC! I should never have been executable.  How did this happen, you monster!\n");
    exit(EXIT_FAILURE);
}

#endif
