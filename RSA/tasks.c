# include <openssl/bn.h>
# include <stdio.h>

# define NBITS 256

void printBN(char *msg, BIGNUM * a) {
    // convert the bignum to number string
    /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
    char * number_str = BN_bn2hex(a);

    printf("%s %s\n", msg, number_str);

    OPENSSL_free(number_str);
}

int main(void) {
    // Structure to hold temporary bignum variables
    BN_CTX *ctx = BN_CTX_new();
    // Task 1 - Private key

    // Declare bignum vars
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *ONE = BN_new();
    BIGNUM *p_minus = BN_new();
    BIGNUM *q_minus = BN_new();
    BIGNUM *z = BN_new();
    BIGNUM *d = BN_new();

    // Initialize p, q and e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_dec2bn(&ONE, "1");

    // printBN("p = ", p);
    // printBN("q = ", q);
    // printBN("e = ", e);

    BN_mul(n, p, q, ctx);
    BN_sub(p_minus, p, ONE);
    BN_sub(q_minus, q, ONE);
    BN_mul(z, p_minus, q_minus, ctx);
    BN_mod_inverse(d, e, z, ctx);

    // printBN("n = ", n);
    // printBN("p - 1 = ", p_minus);
    // printBN("q - 1 = ", q_minus);
    // printBN("z = ", z);
    // printBN("d = ", d);

    printf("*************** TASK 1 - Private Key ***************\n");
    printBN("n = ", n);
    printBN("d = ", d);
    printf("\n");

    // Task 2 - Encrypting

    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();

    BN_hex2bn(&M, "4120746f702073656372657421");
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001"); // e = 65537
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    
    BN_mod_exp(C, M, e, n, ctx);
    
    printf("*************** TASK 2 - Encrypting ***************\n");
    printBN("C = ", C);
    printf("\n");

    // Test for Task 2
    
    // BIGNUM *msg = BN_new();
 
    // BN_mod_exp(msg, C, d, n, ctx);

    // printf("*************** TASK 2 TEST - Decrypting ***************\n");
    // printBN("M = ", msg);
    // printf("Converted Message = A top secret!");
    // printf("\n");

    // Task 3 - Decrypting

    BIGNUM *cipher = BN_new();
    
    BN_hex2bn(&cipher, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    BN_mod_exp(M, cipher, d, n, ctx);
    
    printf("*************** TASK 3 - Decrypting ***************\n");
    printBN("M = ", M);
    printf("Converted Message = Password is dees");
    printf("\n");

    // Task 4 - Digital Signature

    BIGNUM *Sign1 = BN_new();
    BIGNUM *Sign2 = BN_new();
    BIGNUM *M1 = BN_new();
    BIGNUM *M2 = BN_new();

    BN_hex2bn(&M1, "49206f776520796f752024323030302e"); // I owe you $2000.
    BN_hex2bn(&M2, "49206f776520796f752024333030302e"); // I owe you $3000.

    BN_mod_exp(Sign1, M1, d, n, ctx);
    BN_mod_exp(Sign2, M2, d, n, ctx);

    printf("*************** TASK 4 - Digital Signature ***************\n");
    printBN("Original Signature = ", Sign1);
    printBN("Modified Signature = ", Sign2);
    printf("\n");

    // Task 5 - Verifying a Signature

    BIGNUM *Sign = BN_new();
    BIGNUM *Sign_corr = BN_new();
    BIGNUM *M3 = BN_new();
    BIGNUM *M_corr = BN_new();

    BN_hex2bn(&M, "4c61756e63682061206d697373696c652e"); //Launch a missile.
    BN_hex2bn(&Sign, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&Sign_corr, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    BN_mod_exp(M3, Sign, e, n, ctx);
    BN_mod_exp(M_corr, Sign_corr, e, n, ctx);

    printf("*************** TASK 5 - Verifying a Signature ***************\n");
    printBN("Original Message = ", M);
    printBN("Signature Message = ", M3);
    printBN("Corrupted Signature Message = ", M_corr);
    printf("\n");

    // Task 6

    return (0);
}
