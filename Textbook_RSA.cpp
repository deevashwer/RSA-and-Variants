#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <sys/time.h>

#define key_length 2048
#define value_e 65537

using namespace std;

mpz_t zero, one, two;

struct timeval tv;

struct public_key{
    mpz_t n, e;
};

void generate_random(mpz_t x, int bit_size){
    gettimeofday(&tv, NULL);
    srand(tv.tv_usec + tv.tv_sec*1000000);
    mpz_t tmp;
    mpz_init(tmp);
    mpz_mul_2exp(x, one, bit_size - 1);
    for(int i = bit_size - 32; i >= 0; i -= 32){
        mpz_set_ui(tmp, rand());
        mpz_mul_2exp(tmp, tmp, i);
        mpz_add(x, x, tmp);
    }
    mpz_add_ui(x, x, rand());
    mpz_clear(tmp);
}

void find_prime(mpz_t x, int bit_length) {
    mpz_t temp;
    mpz_init(temp);
    generate_random(x, bit_length);
    mpz_nextprime(x, x);
    mpz_sub(temp, x, one);
    while(mpz_gcd_ui(NULL, temp, value_e) != 1){
        generate_random(x, bit_length);
        mpz_nextprime(x, x);
        mpz_sub(temp, x, one);
    }
    mpz_clear(temp);
}

class cryptosystem{
public:
    public_key pk;
    mpz_t sk;
    mpz_t p, q, phi_n;
    
    cryptosystem(){
        mpz_t temp;
        mpz_inits(pk.n, pk.e, sk, p, q, phi_n, temp, NULL);
        mpz_set_ui(pk.e, value_e);
        find_prime(p, key_length/2);
        do{
            find_prime(q, key_length/2);
        }while(mpz_cmp(p, q) == 0);
        mpz_mul(pk.n, p, q);
        mpz_sub(temp, p, one);
        mpz_set(phi_n, temp);
        mpz_sub(temp, q, one);
        mpz_mul(phi_n, phi_n, temp);
        mpz_invert(sk, pk.e, phi_n);
        mpz_clear(temp);
    }
    
    void encrypt(mpz_t ct, mpz_t m){
        mpz_powm(ct, m, pk.e, pk.n);
    }
    
    void decrypt(mpz_t m, mpz_t ct){
        mpz_powm(m, ct, sk, pk.n);
    }
};

class ciphertext{
public:
    mpz_t value;
    cryptosystem* pkc;
    
    ciphertext(){
        mpz_init(value);
    }
    
    ciphertext(mpz_t m, cryptosystem* PKC){
        mpz_init(value);
        pkc = PKC;
        PKC->encrypt(value, m);
    }
    
    void custom_setup(mpz_t val, cryptosystem* PKC){
        mpz_init(value);
        mpz_set(value, val);
        pkc = PKC;
    }
    
    void initialize(mpz_t m, cryptosystem* PKC){
        mpz_init(value);
        pkc = PKC;
        PKC->encrypt(value, m);
    }
    
    void print(){
        mpz_t temp;
        mpz_init(temp);
        pkc->decrypt(temp, value);
        cout << "Plaintext: " << temp << endl;
        mpz_clear(temp);
    }
    
    ciphertext operator*(ciphertext& ct){
        ciphertext result;
        result.pkc = this->pkc;
        mpz_mul(result.value, this->value, ct.value);
        mpz_mod(result.value, result.value, pkc->pk.n);
        return result;
    }
};

int main() {
    mpz_inits(zero, one, two, NULL);
    mpz_set_ui(zero, 0);
    mpz_set_ui(one, 1);
    mpz_set_ui(two, 2);
    cryptosystem pkc;
    /*mpz_t pt;
     mpz_init(pt);
     mpz_set_ui(pt, 534);*/
    ciphertext result(one, &pkc);
    ciphertext ct[10];
    for(int i = 0; i < 10; i++){
        ct[i].initialize(two, &pkc);
        result = result * ct[i];
        cout << i << " ";
        result.print();
    }
    return 0;
}
