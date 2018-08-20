
#include <iostream>
#include <string>
#include <ctime>
#include <cstdlib> // strtol
#include <unistd.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <math.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <unistd.h>

#include <opencv2/opencv.hpp>

#include "sloth.h"


#define ITERATIONS 155000
#define LOG_P 2048 // multiple of 512
#define ERR_IO     -1
#define ERR_MALLOC -2
#define ERR_NULL   -3
#define ENOMEM -4

/*
 * 
 * */
 


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
 
int digest(const char *string, char outputBuffer[], const std::string digest_name)
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

// digest_file("path/to/the/file/to.hash", output_with_enough_space_available, "SHA512")
int digest_file(const char *path, char outputBuffer[], const std::string digest_name)
{
    FILE *file = fopen(path, "rb");
    if(!file) return 1;
    
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
    
    const int bufSize = 8*4096;
    unsigned char *buffer = (unsigned char *)malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return ENOMEM;
    int counter = 0;
    while((bytesRead = fread(buffer, 1, bufSize, file)) && (counter++<100))
    {
        EVP_DigestUpdate(mdctx, buffer, bytesRead);
    }

    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    unsigned int i = 0;
    for(i = 0; i < md_len; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    
    for (i = 0; i < md_len; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    
    outputBuffer[i * 2] = '\0';
    fclose(file);
    free(buffer);
    return 0;
}

int getSlothResults(const char* outFile, char witness[], char commitment[], char outputBuffer[], char string[], int bits, int iterations){
    
    /* Erreur si le nom du fichier est null */
    if(outFile ==NULL){
        return ERR_NULL;
    }
    FILE* sortie;
    /* Ouverture du fichier en écriture */
    sortie = fopen(outFile, "w");
    /* on teste si l'ouverture du flot s'est bien réalisée */
    if (sortie == NULL) {
        fprintf(stderr,"Erreur: le fichier %s ne peut etre ouvert en écriture !\n", outFile);
        return ERR_IO; 
    }

    /* On écrit les résultats */
    std::cout << commitment << std::endl;
    sloth(witness, outputBuffer, string, bits, iterations);
    fprintf(sortie, "%s\n", commitment);
    fprintf(sortie, "%s\n", witness);
    fprintf(sortie, "%s\n", outputBuffer);
    fclose(sortie);
    return 0;
    
}

void digest_img_and_file( const char *img_filename, const char *tweet_filename, char outputBuffer[], const std::string digest_name){
    
    digest_file(tweet_filename, outputBuffer, digest_name);
    std::string strtweet = outputBuffer;

    digest_file(img_filename, outputBuffer, digest_name);
    std::string strimg = outputBuffer;

    sloth_digest(outputBuffer, (strtweet + strimg).c_str());
        
}

void image_capture (std::string file_name, cv::VideoCapture camera) {
    int frame_width = 1280;
    int frame_height = 720;
    
    camera.set(CV_CAP_PROP_FRAME_WIDTH, frame_width);
    camera.set(CV_CAP_PROP_FRAME_HEIGHT, frame_height);
    
    
    cv::Mat frame;
    camera >> frame; // get a new frame from camera
    
    
    imwrite(file_name, frame);
}   

int main(int argc, char *argv[]){
    
    
    std::string twitter_file_name("/Users/trx/projetunicorn/unicorn/tweets.txt"); //default
    std::string data_file_name("/Users/trx/projetunicorn/unicorn/data.txt"); //fichier des données par defaut
    std::string img_file_name("/Users/trx/projetunicorn/unicorn/img.jpg"); //fichier des données par defaut
    
    int iterations = ITERATIONS;
    int log_p = LOG_P;
    
    if(argc >1){
        for (int i = 1; i < argc;){
            //on prend le premier caractère du ième argument
            if(argv[i][0] == '-'){
                switch (argv[i][1]){
                    case 'o': {
                        data_file_name = argv[i+1];
                        i += 2;
                        break;
                    }
                    case 'i': {
                        iterations = strtol(argv[i+1], NULL, 10); //on transforme l'argument iterations, reçu en tant que string, en int
                        i += 2;
                        break;
                    }
                    case 'l': {
                        log_p = strtol(argv[i+1], NULL, 10); //pareil pour logp
                        i += 2;
                        break;
                    }
                    case 'k': {
                        twitter_file_name = argv[i+1];
                        i += 2;
                        break;
                    }
                    default: {
                        i += 1;
                    }
                }
            }
            else {
                i = i + 1;
            }
        }
    }
     

    char seed[129], commitment_seed[129], slothed[129], witness[(log_p/4) + 1]; 
    
    cv::VideoCapture camera(0); // open the default camera
    if(!camera.isOpened()) {  // check if we succeeded
        std::cout << "ERROR: Failed to connect to the webcam" << std::endl;
        return -1;
    }

    image_capture(img_file_name,camera);
    
    /*hash rand + contenu du fichier des tweets*/
    digest_img_and_file(img_file_name.c_str(), twitter_file_name.c_str(), seed, "SHA512");
    

    //digest(seed, seed, "SHA512");
    //std::cout  << seed << std::endl;

    digest(seed, commitment_seed, "SHA512");
    
    /* On écrit dans le fichier les valeurs calculées: witness, commitment et slothed */
    
    int err =0;
    err = getSlothResults(data_file_name.c_str(), witness, commitment_seed, slothed, seed, log_p, iterations);
    if(err!=0) return err;
    
    
    int verif;
    verif = sloth_verification(witness, slothed, seed, log_p, iterations);
    
    //std::cout << "verification:\t" << (verif ? "SUCCESS" : "FAILURE") << std::endl;
    
    return 0;
}

