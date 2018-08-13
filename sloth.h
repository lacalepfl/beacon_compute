#ifndef SLOTH_H
#define SLOTH_H

#include <cstdio>
#include <ctime>

void sloth(char witness[], char outputBuffer[], char string[], int bits, int iterations);

int sloth_verification(const char witness[], const char final_hash[], const char input_string[], int bits, int iterations);

int sloth_digest(char outputBuffer[], const char *string);

#endif // SLOTH_H
