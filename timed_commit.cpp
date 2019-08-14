#include <ctime>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <math.h>

#include <string.h>

#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>

#include "gmp.h"

#include "timed_commit.h"


typedef struct{
  mpz_t *result;
  std::string s;
  int i;
  int w;
}thread_param;


// digest("The string to hash", output_with_enough_space_available, "SHA512")

//digest = le hasher

/*1er etape de l'algo avant de faire les racines carrees et tout cest de prendre le gros fichier ou les donnees 
 * et de le compresser avec une fonction de hashage (sha standard implementee dans openssl)
 * l'entree de la fonction cest string a hasher, output buffer = resultat hashé, et le 3ieme cest la fonction de hashage que 
 * l'on veut utiliser (donc dans ce cas digest_name sera sha512)
 * */
 
 /*les deux points std::string veulent dire que ce type string vient de l'espace de nom (ou librairie) std
  * pour ne pas utiliser :: on peut importer le namespace std comme on a fait pour cv et on pourra alors directement ecrire 
  * string au lieu de std::string
  * */
 
static int digest(const char *string, char outputBuffer[], const std::string digest_name)
{
    //openssl pour faire du hashage
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    
    OpenSSL_add_all_digests();
    
    md = EVP_get_digestbyname(digest_name.c_str());
    if(!md) {
        std::cout << "Unknown message digest" << digest_name << std::endl;
        return 1;
    }
    
    mdctx = EVP_MD_CTX_create();
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, string, strlen(string));
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    
    unsigned int i;
    for (i = 0; i < md_len; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    
    outputBuffer[i * 2] = '\0';
    
    return 0;
}

static void next_prime(mpz_t p, const mpz_t n) {
    if (mpz_even_p(n)) mpz_add_ui(p,n,1);
    else mpz_add_ui(p,n,2);
    while (!mpz_probab_prime_p(p, 25)) mpz_add_ui(p,p,2);
}

static void prev_prime(mpz_t p, const mpz_t n) {
    if (mpz_even_p(n)) mpz_sub_ui(p,n,1);
    else mpz_sub_ui(p,n,2);
    while (!mpz_probab_prime_p(p, 25)) mpz_sub_ui(p,p,2);
}

// the sqrt permutation as specified in the paper (returns a sqrt of either input or -input)
static void sqrt_permutation(mpz_t result, const mpz_t input, const mpz_t p, const mpz_t e) {
  mpz_t tmp;
  mpz_init(tmp);
  if (mpz_jacobi(input, p) == 1) {
    mpz_powm(tmp, input, e, p);
    if (mpz_even_p(tmp)) mpz_set(result, tmp);
    else mpz_sub(result, p, tmp);
  }
  else {
    mpz_sub(tmp, p, input);
        mpz_powm(tmp, tmp, e, p);
    if (mpz_odd_p(tmp)) mpz_set(result, tmp);
    else mpz_sub(result, p, tmp);
  }

  mpz_clear(tmp);
}

// inverse of sqrt_permutation, so basicaly computes squares
static void invert_sqrt(mpz_t result, const mpz_t input, const mpz_t p) {
  mpz_t tmp;
  mpz_init(tmp);
  if (mpz_even_p(input)) {
    mpz_mul(tmp, input, input);
    mpz_mod(result, tmp, p);
  }
  else {
    mpz_mul(tmp, input, input);
    mpz_mod(tmp, tmp, p);
    mpz_sub(result, p, tmp);  
  }

  mpz_clear(tmp);
}

// computes input1 ^ flip ^ flip ^ ... ^ flip for the minimal number of "^ flip" (at least 1, at most 2) such
// that the result is smaller than mod
static void xor_mod(mpz_t result, const mpz_t input1, const mpz_t flip, const mpz_t mod) {
    mpz_xor(result,input1,flip);
    while (mpz_cmp(result, mod) >= 0 || mpz_cmp_ui(result, 0) == 0) {
        mpz_xor(result,result,flip);
    }
}

void *generate_prime( void* p){
  thread_param* param= ((thread_param *)p);

  int rest=(param->w)*128;
  int charpointer=0;
  char hexa[rest +1];
  char hash[129];
  long i=param->i;

  std::stringstream convert;

  convert<<std::hex<<i;
  digest((param->s+ convert.str()).c_str(), hash,  "SHA512");
  while(hash[0]<'8'){
    digest(hash, hash,  "SHA512");
  }
  i++;
  rest-=128;

  while(rest>0)
        {
        strncpy(hexa+charpointer,hash,128);
        charpointer+=128;

        convert.str(std::string());
        convert<<std::hex<<i;
        digest((param->s+ convert.str()).c_str(), hash,  "SHA512");
        i++;
        rest-=128;
        }

  strncpy(hexa+charpointer,hash,128+rest);

  mpz_set_str(*(param->result),hexa,16);
  next_prime(*(param->result),*(param->result));

}


void generate_commit(char** N, char** P, char** Q, char** C, char** k, char* S, char* img_hash, long bitlength_qp, long iterations, long aes_klength){
  mpz_t Nm,Cm,km, ktrunc, Pminus, Qminus, phiN, expf, expe;
  mpz_t primes[2];
  char bufdigest[129];

  mpz_init(Nm);
  mpz_init(primes[0]);
  mpz_init(primes[1]);
  mpz_init(Cm);
  mpz_init(km);
  mpz_init(ktrunc);
  mpz_init(Pminus);
  mpz_init(Qminus);
  mpz_init(phiN);
  mpz_init(expf);
  mpz_init_set_ui(expe,2);

  digest(S, bufdigest,  "SHA512");
  mpz_set_str(Cm,bufdigest,16);

  // generate primes
  pthread_t threads[2];
  thread_param params[2];
  params[0].result = &primes[0];
  params[0].s = img_hash;
  params[0].i = 1;
  params[0].w = 2;
  params[1].result = &primes[1];
  params[1].s = img_hash;
  params[1].i = 3;
  params[1].w = 2;

  /*pthread_create(&threads[0], NULL, &generate_prime, (void *)&params[0]);
  pthread_create(&threads[1], NULL, &generate_prime, (void *)&params[1]);

  pthread_join(threads[0],NULL); 
  pthread_join(threads[1],NULL);*/

  generate_prime((void *)&params[0]);
  generate_prime((void *)&params[1]); 

  //-----------------


  mpz_sub_ui(Pminus, primes[0], 1);
  mpz_sub_ui(Qminus, primes[1], 1);

  mpz_mul(phiN, Pminus, Qminus);

  mpz_mul(Nm, primes[0], primes[1]);


  //compute
  mpz_powm_ui (expf, expe, iterations, phiN);
  mpz_powm (km, Cm, expf, Nm);
  //------

  mpz_tdiv_r_2exp(ktrunc,km,aes_klength);
  *k=mpz_get_str(NULL,36,ktrunc);
  *N=mpz_get_str(NULL,16,Nm);
  *P=mpz_get_str(NULL,16,primes[0]);
  *Q=mpz_get_str(NULL,16,primes[1]);
  *C=mpz_get_str(NULL,16,Cm);


  mpz_clear(Nm);
  mpz_clear(primes[0]);
  mpz_clear(primes[1]);
  mpz_clear(Cm);
  mpz_clear(km);
  mpz_clear(ktrunc);
  mpz_clear(Pminus);
  mpz_clear(Qminus);
  mpz_clear(phiN);
  mpz_clear(expf);
  mpz_clear(expe);
}

void force_open(char** k,const char* C,const char* N, long iterations, long aes_klength){
  mpz_t Nm,Pm,Qm,Cm,km, ktrunc, expf, expe;

  mpz_init_set_str(Nm,N,16);
  mpz_init_set_str(Cm,C,16);
  mpz_init(km);
  mpz_init(ktrunc);
  mpz_init(expf);
  mpz_init_set_ui(expe,2);

  //compute
  mpz_pow_ui (expf, expe, iterations);
  mpz_powm (km, Cm, expf, Nm);
  //------

  mpz_tdiv_r_2exp(ktrunc,km,aes_klength);
  *k=mpz_get_str(NULL,36,ktrunc);


  mpz_clear(Nm);
  mpz_clear(Cm);
  mpz_clear(km);
  mpz_clear(ktrunc);
  mpz_clear(expf);
  mpz_clear(expe);
}
