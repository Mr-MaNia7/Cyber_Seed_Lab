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

    // TASK 6 - Manually Verifying an X.509 Certificate

	// BIGNUM* n = BN_new();
	BIGNUM* bn = BN_new();
	// BIGNUM* e = BN_new();
	BIGNUM* hash = BN_new();
	
    BN_hex2bn(&n, "B6E02FC22406C86D045FD7EF0A6406B27D22266516AE42409BCEDC9F9F76073EC330558719B94F940E5A941F5556B4C2022AAFD098EE0B40D7C4D03B72C8149EEF90B111A9AED2C8B8433AD90B0BD5D595F540AFC81DED4D9C5F57B786506899F58ADAD2C7051FA897C9DCA4B182842DC6ADA59CC71982A6850F5E44582A378FFD35F10B0827325AF5BB8B9EA4BD51D027E2DD3B4233A30528C4BB28CC9AAC2B230D78C67BE65E71B74A3E08FB81B71616A19D23124DE5D79208AC75A49CBACD17B21E4435657F532539D11C0A9A631B199274680A37C2C25248CB395AA2B6E15DC1DDA020B821A293266F144A2141C7ED6D9BF2482FF303F5A26892532F5EE3");
	BN_hex2bn(&e, "65537");
	BN_hex2bn(&bn, "6b6d79cfa0dbc1d9db040610284abd653e152d9accd2c157f73883b09f9212c4b7b0976100ee3e0824f6487133d985d49dc750f8ddaa04a864907bd99b71504bab002151c92cfd31973c19be97c6c083a475938a0bcab331b40b4c5830b37462bfef2b50fa8e2804c9b3b397f7c7c72366a515234615ec4752c61d5d6f8a7c8c0ada53516eec1462d3e36f0e111489067e3506641400a269e903714b841c77a53382f0ab0dfb67407b01bb234720ba2f6443ee456e49342513afe115ee8553f2f800e9a9096694eee1dce8434717ff34fe50de2bb92c03707146015a0bc7e0bc34c415cfc6ad67259967bd3e2083e11905926112a0ae5294c3631d5236bed6fe");

    BN_mod_exp(hash, bn, e, n, ctx);
    // BN_mod_exp(C, M, e, n, ctx);

    printf("*************** TASK 6 - Manually Verifying an X.509 Certificate ***************\n");
	printBN("Public Key = ", n);
	printBN("Hash = ", hash);
	printf("Pre-computed Hash = 324fa17fc16bbff74ca2b1b4ccd0e645366460ffb970f6454f7b3d661cb54be9");
	printf("\n");

    return (0);
}
