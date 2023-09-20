#include <iostream>
#include <string>
#include <vector>
#include <stdio.h>
#include <exception>

#include <json/json.h>  // https://github.com/nlohmann/json
#include <openssl/bn.h>  // https://github.com/openssl/openssl
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <httplib.h>  // https://github.com/yhirose/cpp-httplib
#include "jwt-cpp/jwt.h"  // https://github.com/Thalhammer/jwt-cpp

#define PORT 8080
using namespace std;
using namespace httplib;
using namespace Json;

Server svr;

string priv_key; // Latest Private Key string
string pub_key; // Latest Public Key string 
string modulusStr; // Latest Public Key Modulus component (binary string)
string exponentStr; // Latest Public Key Exponent component (binary string)

Value jwk; // JWK template
Value jwks; // JWKS structure
int kid = 0; // Key ID value

// Generates the seed buffer for RSA key pair generation
const void* getSeedBuffer(int num){
    size_t bufferSize = num*sizeof(int);
    int *buffer = new int[num];
    for(int i=0; i<num; ++i)
        buffer[i] = 0;

    return static_cast<const void *>(buffer);
}

// Base64URL encoder algorithm - NOT ORIGINAL - CODE SOURCE BELOW
// https://gist.github.com/darelf/0f96e1d313e1d0da5051e1a6eff8d329
std::string base64_encode(const std::string & in) {
    const char base64_url_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

    std::string out;
    int val =0, valb=-6;
    size_t len = in.length();
    unsigned int i = 0;
    for (i = 0; i < len; i++) {
        unsigned char c = in[i];
        val = (val<<8) + c;
        valb += 8;
        while (valb >= 0) {
        out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
        valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
    }
    return out;
}

// Generates the JWKS structure
void GenerateJWKS(string pub_key){
    jwk["kty"] = "RSA";
    jwk["use"] = "sig";
    jwk["n"] = base64_encode(modulusStr);
    jwk["e"] = base64_encode(exponentStr);
    jwk["kid"] = to_string(kid);
    jwk["alg"] = "RS256";

    jwks["keys"].append(jwk);

    // Prints updated JWKS structure to server terminal (for testing purposes)
    cout << jwks.toStyledString() << endl << endl;
    return;
}

// Generates either a vaild or expired token and returns the token string
string GenerateJWT(bool expired){
    if(expired){ // Generates Expired Token
        auto token = jwt::create() 
            .set_issuer("auth0")
            .set_type("JWT")
            .set_key_id(to_string(kid))
            .set_issued_at(chrono::system_clock::now())
            .set_expires_at(chrono::system_clock::now() - chrono::seconds{36000}) // Experation set to 10 hours before issued time
            .sign(jwt::algorithm::rs256("", priv_key, "", ""));
        kid++;
        return token;
    }
    else{ // Generates Valid Token
        auto token = jwt::create() 
            .set_issuer("auth0")
            .set_type("JWT")
            .set_key_id(to_string(kid))
            .set_issued_at(chrono::system_clock::now())
            .set_expires_at(chrono::system_clock::now() + chrono::seconds{36000}) // Experation set to 10 hourse after issued time
            .sign(jwt::algorithm::rs256("", priv_key, "", ""));
        kid++;
        return token;
    }
}

// RSA Key Pair Generation
bool RSAKeyGen(bool expired){
    // Set buffer and seed values
    const void *buffer = getSeedBuffer(1000);
    RAND_seed(getSeedBuffer(1000), 1000);
    delete[] static_cast<const int *>(buffer);

    // Create RSA
    RSA *rsa = RSA_new();
    if(rsa == NULL)
    {
        cout << "ERROR: RSA FAIL\n";
        return NULL;
    }

    // Create BIGNUM value
    BIGNUM *bne = BN_new();
    if(bne == NULL)
    {
        cout << "ERROR: BIGNUM FAIL\n";
        return NULL;
    }
    if(BN_set_word(bne, RSA_F4) !=1)
    {
        cout << "ERROR: BN_set_word FAIL\n";
        return NULL;
    }

    unsigned int bits = 2048;
    unsigned long e = RSA_F4;

    // Generate key pair
    if(RSA_generate_key_ex(rsa, bits, bne, NULL) != 1){
        cout << "ERROR: Generating RSA Key Pair" << endl;
        return 0;
    }

    // Free value
    BN_free(bne);

    BIO *bio_priv = BIO_new(BIO_s_mem());
    BIO *bio_pub = BIO_new(BIO_s_mem());

    // Write Public and private keys into strings
    PEM_write_bio_RSAPrivateKey(bio_priv, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(bio_pub, rsa);

    char *priv_key_str, *pub_key_str;
    size_t priv_len = BIO_pending(bio_priv);
    size_t pub_len = BIO_pending(bio_pub);

    priv_key_str = (char*)malloc(priv_len + 1);
    pub_key_str = (char*)malloc(pub_len + 1);

    BIO_read(bio_priv, priv_key_str, priv_len);
    BIO_read(bio_pub, pub_key_str, pub_len);

    priv_key_str[priv_len] = '\0';
    pub_key_str[pub_len] = '\0';

    priv_key = priv_key_str;
    pub_key = pub_key_str;

    // Get modulus and exponent from public key
    const BIGNUM *expBN = RSA_get0_e(rsa);
    const BIGNUM *modBN = RSA_get0_n(rsa);

    if(!expBN){
        cout << "NO EXP\n";
    }

    if(!modBN){
        cout << "NO MOD\n";
    }

    int numBytesExp = BN_num_bytes(expBN);
    int numBytesMod = BN_num_bytes(modBN);

    vector<unsigned char> binExp(numBytesExp);
    vector<unsigned char> binMod(numBytesMod);

    BN_bn2bin(expBN, binExp.data());
    BN_bn2bin(modBN, binMod.data());

    string tempExp(binExp.begin(), binExp.end());
    string tempMod(binMod.begin(), binMod.end());

    // Modulus and exponent strings (binary)
    exponentStr = tempExp;
    modulusStr = tempMod;

    // Free memory
    BIO_free_all(bio_priv);
    BIO_free_all(bio_pub);
    RSA_free(rsa);
    free(priv_key_str);
    free(pub_key_str);

    // If vaild key generated, add key to JWKS
    if(!expired){
        GenerateJWKS(pub_key);
    }

    return 1;
}

// HTTP Handlers

void handle_get(const Request& req, Response& res){ // Handles the GET /jwt.json request
    printf("Send JWKS\n");
    res.set_content(jwks.toStyledString(), "application/json");
    res.status = 200;
}
void handle_dead_end(const Request& req, Response& res){  // Returns a Status: 405 
    res.status = 405;
}

int main(){
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    RAND_poll();

    // /jwks.json request handlers
    svr.Get("/.well-known/jwks.json", handle_get);
    svr.Post("/.well-known/jwks.json", handle_dead_end);
    svr.Put("/.well-known/jwks.json", handle_dead_end);
    svr.Delete("/.well-known/jwks.json", handle_dead_end);
    svr.Patch("/.well-known/jwks.json", handle_dead_end);
    svr.Options("/.well-known/jwks.json", handle_dead_end);

    // /auth handlers
    svr.Get("/auth", handle_dead_end);
    svr.Post("/auth", [&](const auto& req, auto& res){
        printf("Auth call\n"); // Print to server terminal that an Auth call has been made (for testing)
        
        bool expired = req.has_param("expired");

        cout << "Expired value: " << expired << endl; // Print binary value if query parameter is expired (for testing)

        // Generate new keypair - error if failed
        if(RSAKeyGen(expired) != 1){
            printf("Error: RSA Key Generation Failed\n");
            return 0;
        }
        
        // Generate JWT
        string generatedJWT = GenerateJWT(expired);

        // Send JWT to client
        res.set_content(generatedJWT, "text/plain");
        res.status = 200;
    });
    svr.Put("/auth", handle_dead_end);
    svr.Delete("/auth", handle_dead_end);
    svr.Patch("/auth", handle_dead_end);
    svr.Options("/auth", handle_dead_end);

    svr.listen("127.0.0.1", PORT);

    return 0;
}