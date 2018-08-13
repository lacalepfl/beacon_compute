#include <ctime>
#include <string>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <string.h>

#include "gmp.h"

#include "sloth.h"

void next_prime(mpz_t p, const mpz_t n) {
    if (mpz_even_p(n)) mpz_add_ui(p,n,1);
    else mpz_add_ui(p,n,2);
    while (!mpz_probab_prime_p(p, 25)) mpz_add_ui(p,p,2);
}

void prev_prime(mpz_t p, const mpz_t n) {
    if (mpz_even_p(n)) mpz_sub_ui(p,n,1);
    else mpz_sub_ui(p,n,2);
    while (!mpz_probab_prime_p(p, 25)) mpz_sub_ui(p,p,2);
}

// the sqrt permutation as specified in the paper (returns a sqrt of either input or -input)
void sqrt_permutation(mpz_t result, const mpz_t input, const mpz_t p, const mpz_t e) {
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
void invert_sqrt(mpz_t result, const mpz_t input, const mpz_t p) {
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
void xor_mod(mpz_t result, const mpz_t input1, const mpz_t flip, const mpz_t mod) {
    mpz_xor(result,input1,flip);
    while (mpz_cmp(result, mod) >= 0 || mpz_cmp_ui(result, 0) == 0) {
        mpz_xor(result,result,flip);
    }
}

// SHA512
int sloth_digest(char outputBuffer[], const char *string)
{
    
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    
    OpenSSL_add_all_digests();
    
    md = EVP_get_digestbyname("SHA512");
    if(!md) {
        std::cout << "Unknown message digest SHA512" << std::endl;
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

// generates the prime (of bit length "bits"), and the initial value in the field from the data "string" => donc genere 
// p et u = h(s) 
// bits must be a multiple of 512

/*
 * bits = la longueur en bits voulue pour notre nombre premier (ex:2048)
 * cest un multiple de 512 car sha512 nous rend 512 bits
 * on hash nos données et chaque fois que je hash ca me donne 512 bits et comme je sais que je dois
 * construire 2008 bits je hash 4 fois et on obtient alors un nombre codé sur 2008 bits mais il n'est pas forcemment premier
 * du coup j'implement next prime pour prendre le prochain nombre premier (je commence par ce nombre sil est premier jle 
 * garde sinon je prends le suivant
 * */
void sloth_preprocessing(mpz_t p, mpz_t seed, const char string[], int bits) {
    
    //mais donc str est initialisé a string, les données que l'on veut hacher
    std::string str = string;
    
    // find the prime
    int nbr_blocks = bits / 512;
    char hexa[bits/4 + 1]; // number of hexadecimal charater + 1 => car 1 nombre en hexa occupe 4 bits
    
    //je hash le nombre de fois necessaire (4 blocs pour 2048 par exemple)
    for (int i = 0; i < nbr_blocks; ++i) {
		/* c_str Returns a pointer to an array that contains a null-terminated sequence of characters*/
		//donc on hache les données concatenees a la sequence prime et 0i avec i allant de 0 a 3 pour ne pas 
		//avoir a chaque fois pour chaque bloc la meme valeur du hash

        sloth_digest(hexa + (128 * i), (str + "prime" + (char)('0' + i)).c_str());
    }
    
    mpz_t tmp;
    mpz_init(tmp);
    
    //initialise la valeur de p depuis hexa, a null-terminated C string in base base.
    //donc la notre p est a nombre de "bits" bits correspondant a la valeur de hachage nbr_blocks fois,
    //de string[], les données
    
    mpz_set_str(p, hexa, 16);
    
    //Test bit (bits-1) in p and return 0 or 1 accordingly, donc si ce bit ==0 elle l'inverse 
    //et le rend = 1 car sinon ca veut dire que le dernier bit est 0 et donc divisible par 2 or nous
    //on veut un nombre premier
    if (!mpz_tstbit(p,bits - 1)) mpz_combit(p, bits - 1);
    
    //generation du nombre premier tant que celui ci 
    //n'est pas congru à 3 mod 4
    do {
		next_prime(p,p);
			//Sets tmp to p mod 4. The sign of the divisor is ignored; the result is always non-negative.
    }while (mpz_mod_ui(tmp, p, 4) != 3);
    
    // find the seed
    for (int i = 0; i < nbr_blocks; ++i) {
		//On hache cette fois ci la sequence de données + le string seed et 0i  
		//on rajoute prime et seed pour avoir des valeurs de hachage differentes pour seed et le nombre premier
        sloth_digest(hexa + (128 * i), (str + "seed" + (char)('0' + i)).c_str());
    }
    
    //initialise seed depuis hexa 
    mpz_set_str(seed, hexa, 16);
    //Sets seed to seed mod p
    mpz_mod(seed, seed, p);
    
    //On libère ce que l'on a alloué
    mpz_clear(tmp);
}

// computes witness = the sloth witness, for the given seed, number of iterations and prime p
void sloth_core(mpz_t witness, const mpz_t seed, int iterations, const mpz_t p) {
    mpz_t a, ones, e;
    //a est initialisé à seed
    mpz_init_set(a, seed);
    
    mpz_init_set_ui(ones, 1);
    mpz_mul_2exp(ones, ones, mpz_sizeinbase(p,2) >> 1); // flip half the bits (least significant)
    mpz_sub_ui(ones, ones, 1);
    
    // compute the exponent for sqrt extraction
    
    mpz_init_set(e, p);
    mpz_add_ui(e, e, 1);
    mpz_tdiv_q_ui(e, e, 4);
    
    for (int i = 0; i < iterations; ++i) {
        //permutation(a, a);
        xor_mod(a,a,ones,p);
        sqrt_permutation(a, a, p, e);
    }
    
    //witness devient a
    mpz_set(witness, a);
    
    mpz_clear(a);
    mpz_clear(ones);
}

// computes witness = the sloth witness, for the given seed, number of iterations ( iterations = l dans la feuille) and prime p
void sloth(char witness[], char outputBuffer[], char string[], int bits, int iterations) {
    mpz_t p, seed_mpz, witness_mpz;
    mpz_init(p);
    mpz_init(seed_mpz);
    mpz_init(witness_mpz);
    sloth_preprocessing(p,seed_mpz,string,bits);
    
    sloth_core(witness_mpz, seed_mpz, iterations, p);
    //Converti witness en un string de digits en base 16
    mpz_get_str(witness, 16, witness_mpz);
    
    //dans output buffer on a maintenant h(witness) = à notre nombre
    //aleatoire recherché
    sloth_digest(outputBuffer, witness);
    
    //faut faire le clear si on init un mpz_t
    mpz_clear(p);
    mpz_clear(seed_mpz);
    mpz_clear(witness_mpz);
}

// checks if the given witness indeed corresponds to the given seed, number of iterations and prime number
int sloth_verification_core(const char witness[], const mpz_t seed, int iterations, const mpz_t p) {
    mpz_t a, ones;
    mpz_init(a);
    mpz_set_str(a, witness, 16);
    
    mpz_init_set_ui(ones, 1);
    mpz_mul_2exp(ones, ones, mpz_sizeinbase(p,2) >> 1);
    mpz_sub_ui(ones, ones, 1);
    
    for (int i = 0; i < iterations; ++i) {
        invert_sqrt(a, a, p);
        //invert_permutation(a, a);
        xor_mod(a,a,ones,p);
    }
    
    int verif = (mpz_cmp(seed, a) == 0); // true if seed == a
    mpz_clear(a);
    mpz_clear(ones);
    
    return verif;
}

// computes witness = the sloth witness, for the given seed, number of iterations and prime p
int sloth_verification(const char witness[], const char final_hash[], const char input_string[], int bits, int iterations) {
    mpz_t p, seed_mpz;
    mpz_init(p);
    mpz_init(seed_mpz);
    
    sloth_preprocessing(p,seed_mpz,input_string,bits);
    
    return sloth_verification_core(witness, seed_mpz, iterations, p);
}

