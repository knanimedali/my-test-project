/* vuln_many.c
 * Educational: intentionally contains many common C vulnerabilities.
 * DO NOT use this code in production or on public networks.
 *
 * Compile for testing with sanitizers:
 *   gcc -Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer vuln_many.c -o vuln_many
 *
 * Use only in an offline sandbox.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define SMALL 32

/* 1) Buffer overflow via strcpy */
void vuln_strcpy(const char *in) {
    char buf[SMALL];
    /* unsafe: no bounds check */
    strcpy(buf, in);
    printf("strcpy -> %s\n", buf);
}

/* 2) Buffer overflow via strcat */
void vuln_strcat(const char *a, const char *b) {
    char buf[SMALL];
    /* unsafe: no space check before concatenation */
    strcpy(buf, a);
    strcat(buf, b);
    printf("strcat -> %s\n", buf);
}

/* 3) Unsafe sprintf (stack overflow) */
void vuln_sprintf(const char *name, const char *desc) {
    char line[64];
    /* unsafe: sprintf can overflow line */
    sprintf(line, "Name: %s Desc: %s", name, desc);
    printf("sprintf -> %s\n", line);
}

/* 4) scanf without width limits (stack overflow) */
void vuln_scanf() {
    char input[16];
    printf("Enter short word: ");
    /* unsafe: %s with no width allows overflow */
    scanf("%s", input);
    printf("scanf -> %s\n", input);
    /* leftover newline in stdin may affect later input */
}

/* 5) Use of gets-like pattern (unsafe input; truncated or buffer overflow) */
void vuln_gets_like() {
    char small[8];
    /* lint: using fgets but ignoring leftover if longer than buffer */
    printf("Type something (may be truncated): ");
    if (fgets(small, sizeof(small), stdin) == NULL) return;
    /* if input longer than 7 chars, it's truncated and rest remains in stdin — logic bugs */
    printf("gets_like -> %s\n", small);
}

/* 6) Format-string vulnerability */
void vuln_format(const char *user_fmt) {
    /* unsafe: passing user-controlled string as format */
    printf(user_fmt);
    printf("\n");
}

/* 7) Use-after-free and double-free */
void vuln_use_after_free_double_free() {
    char *p = malloc(64);
    if (!p) return;
    strcpy(p, "heapdata");
    free(p);
    /* use after free */
    printf("after free -> %s\n", p);
    /* double free */
    free(p);
}

/* 8) Integer overflow when computing allocation size */
void vuln_integer_overflow(size_t n) {
    /* if n is large, n + 1 can wrap to small value -> too small allocation */
    size_t need = n + 1;
    char *buf = malloc(need);
    if (!buf) {
        puts("malloc failed");
        return;
    }
    /* writing n bytes may overflow */
    memset(buf, 'A', n);
    buf[n] = '\0';
    printf("integer_overflow -> %.10s\n", buf);
    free(buf);
}

/* 9) Uninitialized stack variable (use of indeterminate value) */
void vuln_uninitialized() {
    int secret;
    /* reading uninitialized variable -> undefined behaviour / information leak */
    if (secret == 0) {
        printf("secret was zero\n");
    } else {
        printf("secret was non-zero (garbage: %d)\n", secret);
    }
}

/* 10) NULL pointer dereference */
void vuln_null_deref(int flag) {
    char *p = NULL;
    if (flag) {
        p = malloc(8);
        strcpy(p, "ok");
    }
    /* if flag == 0, this deref crashes */
    printf("maybe null -> %s\n", p);
    if (p) free(p);
}

/* 11) Insecure temporary filename (race condition / TOCTOU) */
void vuln_insecure_tempfile() {
    char *tmp = tmpnam(NULL); /* deprecated and insecure */
    if (!tmp) return;
    printf("tmpnam gave: %s\n", tmp);
    /* attacker could create file between tmpnam and fopen */
    FILE *f = fopen(tmp, "w+");
    if (!f) {
        perror("fopen");
        return;
    }
    fprintf(f, "insecure temp content\n");
    fclose(f);
}

/* 12) Insecure file open using user-supplied path (path traversal / arbitrary file write) */
void vuln_insecure_file_write(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("fopen user path");
        return;
    }
    fprintf(f, "writing to user path (unsafe)\n");
    fclose(f);
}

int main(int argc, char **argv) {
    const char *big = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const char *a = "HELLO_";
    const char *b = "WORLD_LONG_DATA_THAT_OVERFLOWS";

    puts("=== vuln_strcpy ===");
    vuln_strcpy(big);

    puts("=== vuln_strcat ===");
    vuln_strcat(a, b);

    puts("=== vuln_sprintf ===");
    vuln_sprintf("Alice", big);

    puts("=== vuln_scanf ===");
    /* Note: call vuln_scanf only if running interactively */
    vuln_scanf();

    puts("=== vuln_gets_like ===");
    vuln_gets_like();

    puts("=== vuln_format ===");
    vuln_format("%x %x %x %x %x"); /* example unsafe format string; avoid running with attacker input */

    puts("=== vuln_use_after_free_double_free ===");
    vuln_use_after_free_double_free();

    puts("=== vuln_integer_overflow ===");
    vuln_integer_overflow((size_t)-1); /* simulate very large n */

    puts("=== vuln_uninitialized ===");
    vuln_uninitialized();

    puts("=== vuln_null_deref (flag=0) ===");
    vuln_null_deref(0);

    puts("=== vuln_insecure_tempfile ===");
    vuln_insecure_tempfile();

    puts("=== vuln_insecure_file_write ===");
    if (argc > 1) {
        vuln_insecure_file_write(argv[1]); /* writes to path supplied by user */
    } else {
        puts("pass a path as argv[1] to see insecure_file_write");
    }

    return 0;
}

