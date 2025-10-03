// vuln.cpp
// Educational: demonstrates several common C/C++ vulnerabilities.
// DO NOT use this code in production.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>

void vuln_strcpy(const char* input) {
    // BUFFER OVERFLOW: copying without bounds check
    char buf[32];
    // unsafe: if input > 31 bytes, this overflows buf
    strcpy(buf, input);
    printf("You said: %s\n", buf);
}

void vuln_format(const char* input) {
    // FORMAT STRING VULNERABILITY: user-supplied format string
    // If input contains "%x" or "%s", printf will treat them as format specifiers.
    printf(input); // unsafe
    printf("\n");
}

void vuln_use_after_free() {
    // USE-AFTER-FREE
    char* p = (char*)malloc(32);
    if (!p) return;
    strcpy(p, "data in heap");
    free(p);
    // Using p after free -> undefined behavior
    printf("After free: %s\n", p); // unsafe
}

void vuln_integer_overflow(size_t len) {
    // INTEGER OVERFLOW leading to buffer size too small
    // Suppose we want to allocate len+1 bytes for a string but len comes from untrusted source.
    size_t size_needed = len + 1; // if len is SIZE_MAX this wraps to 0
    char* buf = (char*)malloc(size_needed);
    if (!buf) {
        puts("malloc failed");
        return;
    }
    // pretend we fill it
    memset(buf, 'A', len);
    buf[len] = '\0'; // could write out-of-bounds if overflow happened
    printf("Buf: %.10s...\n", buf);
    free(buf);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        puts("Usage: ./vuln <input-string>");
        return 1;
    }

    const char* user = argv[1];

    puts("=== vuln_strcpy ===");
    vuln_strcpy(user);

    puts("=== vuln_format ===");
    vuln_format(user);

    puts("=== vuln_use_after_free ===");
    vuln_use_after_free();

    puts("=== vuln_integer_overflow (len=18446744073709551615 simulated) ===");
    // Demonstrate with a large value. Beware: do not run with actual extreme values on limited systems.
    vuln_integer_overflow((size_t)-1);

    return 0;
}

