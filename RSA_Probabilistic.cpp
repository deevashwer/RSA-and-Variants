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

void generate_random(mpz_t x, int bit_size, bool full_range){
    gettimeofday(&tv, NULL);
    srand(tv.tv_usec + tv.tv_sec*1000000);
    mpz_t tmp;
    mpz_init(tmp);
    if(!full_range)
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
    generate_random(x, bit_length, false);
    mpz_nextprime(x, x);
}

void find_generator(mpz_t g, mpz_t m, mpz_t phi_n, mpz_t n){
    mpz_t temp, tmp, two_x;
    mpz_inits(temp, tmp, two_x, NULL);
    mpz_set(temp, two);
    mpz_cdiv_q(two_x, phi_n, m);
    while(true){
        mpz_powm(tmp, temp, two_x, n);
        if(mpz_cmp(tmp, one) != 0)
            break;
        mpz_add(temp, temp, one);
    }
    mpz_set(g, tmp);
    return;
}

class cryptosystem{
public:
    public_key pk;
    mpz_t sk;
    mpz_t p, q, r, t, h, m, phi_n;
    
    cryptosystem(){
        mpz_t temp;
        mpz_inits(pk.n, pk.e, sk, p, q, r, t, h, m, phi_n, temp, NULL);
        mpz_set_ui(pk.e, value_e);
        find_prime(r, key_length/4);
        do{
            find_prime(t, key_length/4);
        }while(mpz_cmp(r, t) == 0);
        
        mpz_mul(temp, two, r);
        do{
            generate_random(p, key_length/4, false);
            mpz_mul(p, p, temp);
            mpz_add(p, p, one);
        }while(mpz_probab_prime_p(p, 35) == 0);
        cout << "Found p" << endl;
        
        mpz_mul(temp, two, t);
        do{
            generate_random(q, key_length/4, false);
            mpz_mul(q, q, temp);
            mpz_add(q, q, one);
        }while(mpz_probab_prime_p(q, 35) == 0);
        cout << "Found q" << endl;
        
        mpz_mul(pk.n, p, q);
        mpz_mul(temp, t, pk.e);
        mpz_invert(sk, temp, r);
        mpz_mul(sk, sk, t);
        
        mpz_sub(temp, p, one);
        mpz_set(phi_n, temp);
        mpz_sub(temp, q, one);
        mpz_mul(phi_n, phi_n, temp);
        
        find_generator(h, t, phi_n, pk.n);
        cout << "Found generator h" << endl;
        find_generator(m, r, phi_n, pk.n);
        cout << "Found generator m" << endl;
        mpz_clear(temp);
    }
    
    void encrypt(mpz_t ct, mpz_t M){
        mpz_t temp;
        mpz_init(temp);
        mpz_powm(ct, m, M, pk.n);
        generate_random(temp, key_length/4, true);
        mpz_powm(temp, h, temp, pk.n);
        mpz_mul(ct, ct, temp);
        mpz_powm(ct, ct, pk.e, pk.n);
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
    //ciphertext result(one, &pkc);
    ciphertext ct[2];
    cout << "m: " << pkc.m << endl;
    for(int i = 0; i < 2; i++){
        cout << "Ciphertext " << i + 1 << endl;
        ct[i].initialize(one, &pkc);
        cout << "Value: " << ct[i].value << endl;
        ct[i].print();
    }
    return 0;
}
