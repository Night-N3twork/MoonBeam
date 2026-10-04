// this is actually so dumb lmao
#ifndef FAKE_STRING_H
#define FAKE_STRING_H

#include <stddef.h>

void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int   memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
int   strcmp(const char *s1, const char *s2);
int   strncmp(const char *s1, const char *s2, size_t n);
char *strstr(const char *haystack, const char *needle);
char *strchr(const char *s, int c);
size_t strnlen(const char *s, size_t maxlen);
char *strncpy(char *dest, const char *src, size_t n);

#endif
