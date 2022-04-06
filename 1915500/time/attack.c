#include "attack.h"

#define BUFFER_SIZE (80)
#define WORD_LENGTH (64)

pid_t pid = 0;

int target_raw[2];
int attack_raw[2];

FILE* target_out = NULL;
FILE* target_in = NULL;

void cleanup(int s) {
    fclose(target_in);
    fclose(target_out);
    close(target_raw[0]); 
    close(target_raw[1]); 
    close(attack_raw[0]); 
    close(attack_raw[1]); 
    if (pid > 0) kill(pid, SIGKILL);
    exit(1); 
}

void get_params(const char *config_file, mpz_t *public_exponent, mpz_t *modulus) {
    FILE *file = fopen(config_file, "r");

    gmp_fscanf(file, "%Zx\n", modulus);
    gmp_fscanf(file, "%Zx", public_exponent);
}

void calc_base(mpz_t *base) {
    mpz_t temp;
    mpz_init(temp);
    mpz_set_ui(temp, 2);
    mpz_pow_ui(*base, temp, WORD_LENGTH);
    mpz_clear(temp);
}

void calc_omega(mpz_t *omega, mpz_t *modulus, mpz_t *base) {
    mpz_set_ui(*omega, 1);
    for (int i = 0; i < WORD_LENGTH; i++) {
        mpz_mul(*omega, *omega, *omega);
        mpz_mul(*omega, *omega, *modulus);
        mpz_mod(*omega, *omega, *base);
    }
    mpz_mul_si(*omega, *omega, -1);
    mpz_mod(*omega, *omega, *base);
}

int calc_modulus_limbs(mpz_t *modulus) {
    size_t size = mpz_size(*modulus);
    return size * (8 / sizeof(mp_limb_t));
}

void calc_rho_sq(mpz_t *rho_sq, mpz_t *modulus, int *modulus_limbs) {
    mpz_t temp;
    mpz_init(temp);
    mpz_set_ui(temp, 2);
    int temp_2 = 2 * *modulus_limbs * WORD_LENGTH;
    mpz_powm_ui(*rho_sq, temp, temp_2, *modulus);
    mpz_clear(temp);
}

void calc_params(mpz_t *base, mpz_t *omega, mpz_t *rho_sq, mpz_t *public_exponent, mpz_t *modulus, int *modulus_limbs) {
    calc_base(base);
    calc_omega(omega, modulus, base);
    *modulus_limbs = calc_modulus_limbs(modulus);
    calc_rho_sq(rho_sq, modulus, modulus_limbs);

    gmp_printf("%Zd %d %Zd\n", *omega, *modulus_limbs, *rho_sq);
}

void calc_private_exponent(mpz_t *private_exponent) {
    
}

void attack(const char *config_file) {
    mpz_t public_exponent, private_exponent, modulus, base, omega, rho_sq;
    mpz_inits(public_exponent, private_exponent, modulus, base, omega, rho_sq, NULL);
    int modulus_limbs, interactions;
    
    get_params(config_file, &public_exponent, &modulus);
    calc_params(&base, &omega, &rho_sq, &public_exponent, &modulus, &modulus_limbs);
    calc_private_exponent(&private_exponent);



    mpz_clears(public_exponent, modulus, base, omega, rho_sq, NULL);




}

int main(int argc, char* argv[]) {
    signal(SIGINT, &cleanup);

    if (pipe(target_raw) == -1) abort();
    if (pipe(attack_raw) == -1) abort();

    pid = fork();
    if (pid > 0) {
        if ((target_out = fdopen(attack_raw[0], "r")) == NULL) abort();
        if ((target_in = fdopen(target_raw[1], "w")) == NULL) abort();
        attack(argv[2]);
    }
    else if (pid == 0) {
        close(STDOUT_FILENO);
        if (dup2(attack_raw[1], STDOUT_FILENO) == -1) abort();
        close(STDIN_FILENO);
        if (dup2(target_raw[0], STDIN_FILENO) == -1) abort();
        execl(argv[1], argv[0], NULL);
    }
    else if (pid < 0) {
        abort();
    }

    cleanup(SIGINT);
    return 0;
}