#ifndef TIMED_COMMIT_H
#define TIMED_COMMIT_H

void generate_commit(char** N, char** P, char** Q, char** C, char** k, char* S, char* img_hash, long bitlength_qp, long iterations, long aes_klength);
void force_open(char** k,const char* C,const char* N, long iterations, long aes_klength);

#endif // TIMED_COMMIT_H
