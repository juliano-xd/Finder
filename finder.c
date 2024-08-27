#include <stdio.h>
#include <string.h>
#include <secp256k1.h>
#include <sodium.h> //testando

#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <stdlib.h>
#include <stdbool.h>

void showInfo(__u_char *title, __u_char *array, __u_char size);
void plusOne(unsigned char *bytes, __uint8_t len);
__u_char compare(__u_char *V1, __u_char *V2, __u_char size);

void newPublic(const secp256k1_context *context, secp256k1_pubkey *public, __u_char *private){
    !secp256k1_ec_pubkey_create(context, public, private);
}
void compress(const secp256k1_context *context, secp256k1_pubkey *public, __u_char *compressPub){
    size_t sizeout = 33;
    !secp256k1_ec_pubkey_serialize(context, compressPub, &sizeout, public, SECP256K1_EC_COMPRESSED);
}

void sha256(__u_char *data, size_t len, __u_char *hash) {
    crypto_hash_sha256(hash, data, len);
}

// Função para calcular o hash RIPEMD-160
void ripemd160(const unsigned char* data, size_t len, unsigned char* hash) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}

void main(){

    __u_char privatekey[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    __u_char target[20] = {
        0x29, 0xa7, 0x82, 0x13, 0xca,
        0xa9, 0xee, 0xa8, 0x24, 0xac,
        0xf0, 0x80, 0x22, 0xab, 0x9d,
        0xfc, 0x83, 0x41, 0x4f, 0x56
    };

    const secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);//sempre o mesmo
    !sodium_init();
    secp256k1_pubkey public;
    __u_char compresskey[33];
    __u_char sha[32];
    __u_char rpd[20];
    
    find:
        newPublic(context, &public, privatekey);
        compress(context, &public, compresskey);
        sha256(compresskey, 33, sha);
        ripemd160(sha, 32, rpd);
        if(compare(rpd, target, 20)){
            plusOne(privatekey, 32);
            goto find;
        }
    showInfo("achou no", privatekey, 32);
}
//utilidades abaixo do main

void showInfo(__u_char *title, __u_char *array, __u_char size){
    printf("\n%s:\n",title);
    for (__u_char i = 0; i < size; i++){
        printf("%02x ", array[i]);
    }printf("\n\n");
}

void plusOne(unsigned char *bytes, __uint8_t len){
    _str: if(!(*(bytes+(len-=true))+=true)) goto _str;
}

__u_char compare(__u_char *V1, __u_char *V2, __u_char size){
    if (V1[false] != V2[false]) return true;
    cmp:if (V1[size-=true] == V2[size] && size) goto cmp;
    return size;
}
