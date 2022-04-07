#include "attack.h"

#define BUFFER_SIZE (80)
#define WORD_LENGTH (64)
#define INITIAL_SAMPLES (2000)

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
}

int interact(mpz_t *ciphertext, int* interactions) {
    (*interactions)++;

    gmp_fprintf(target_in, "%ZX\n", *ciphertext);
    fflush(target_in);

    int time;
    fscanf(target_out, "%d\n%*X", &time);

    return time;
}

void gen_ciphertext_samples_times(mpz_t *ciphertext_samples, unsigned int* ciphertext_times, mpz_t *modulus, int num_samples, gmp_randstate_t *state, int* interactions) {
    for (int i = 0; i < num_samples; i++) {
        mpz_init(ciphertext_samples[i]);
        mpz_urandomm(ciphertext_samples[i], *state, *modulus);
        ciphertext_times[i] = interact(&ciphertext_samples[i], interactions);
    }
}

int mont_mul(mpz_t *result, mpz_t *x, mpz_t *y, int *modulus_limbs, mpz_t *omega, mpz_t *modulus, mpz_t *base) {
    mpz_t temp, temp_2;
    mpz_inits(temp, temp_2, NULL);

    mpz_set_ui(temp, 0);
    mp_limb_t x_0 = mpz_getlimbn(*x, 0);

    for (int i = 0; i < *modulus_limbs; i++) {
        mpz_set_ui(temp_2, 0);
        mpz_add_ui(temp_2, temp_2, mpz_getlimbn(*y, i));
        mpz_mul_ui(temp_2, temp_2, x_0);
        mpz_add_ui(temp_2, temp_2, mpz_getlimbn(temp, 0));
        mpz_mul(temp_2, temp_2, *omega);
        mpz_mod(temp_2, temp_2, *base);

        mpz_addmul_ui(temp, *x, mpz_getlimbn(*y, i));
        mpz_addmul(temp, *modulus, temp_2);
        mpz_fdiv_q_2exp(temp, temp, WORD_LENGTH);
    }

    int reduction = 0;
    if (mpz_cmp(temp, *modulus) >= 0) {
        reduction = 1;
        mpz_sub(temp, temp, *modulus);
    }

    mpz_set(*result, temp);
    mpz_clears(temp, temp_2, NULL);

    return reduction;
}

void calc_ciphertext_monts(mpz_t *ciphertext_monts, mpz_t *ciphertext_samples, int num_samples, mpz_t *rho_sq, int *modulus_limbs, mpz_t *omega, mpz_t *modulus, mpz_t *base) {
    for (int i = 0; i < num_samples; i++) {
        mpz_init(ciphertext_monts[i]);
        mont_mul(&ciphertext_monts[i], &ciphertext_samples[i], rho_sq, modulus_limbs, omega, modulus, base);
    }
}

void mont_exp_init(mpz_t *result, mpz_t *x, mpz_t *rho_sq, int* modulus_limbs, mpz_t *omega, mpz_t *modulus, mpz_t *base) {
    mpz_t temp;
    mpz_init(temp);

    mpz_set_ui(temp, 1);
    mont_mul(result, &temp, rho_sq, modulus_limbs, omega, modulus, base);
    mont_mul(result, result, result, modulus_limbs, omega, modulus, base);
    mont_mul(result, result, x, modulus_limbs, omega, modulus, base);
    mont_mul(result, result, result, modulus_limbs, omega, modulus, base);

    mpz_clear(temp);
}

void calc_m_temps_init(mpz_t *m_temps, mpz_t *ciphertext_monts, int num_samples, mpz_t *rho_sq, int *modulus_limbs, mpz_t *omega, mpz_t *modulus, mpz_t *base) {
    for (int i = 0; i < num_samples; i++) {
        mpz_init(m_temps[i]);
        mont_exp_init(&m_temps[i], &ciphertext_monts[i], rho_sq, modulus_limbs, omega, modulus, base);
    }
}

void calc_private_exponent(mpz_t *private_exponent, mpz_t *public_exponent, mpz_t *modulus, int *modulus_limbs, mpz_t *omega, mpz_t *rho_sq, mpz_t *base, int* interactions) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_t *ciphertext_samples = malloc(sizeof(mpz_t) * INITIAL_SAMPLES);
    unsigned int *ciphertext_times = malloc(sizeof(unsigned int) * INITIAL_SAMPLES);
    mpz_t *ciphertext_monts = malloc(sizeof(mpz_t) * INITIAL_SAMPLES);
    mpz_t *m_temps = malloc(sizeof(mpz_t) * INITIAL_SAMPLES);

    gen_ciphertext_samples_times(ciphertext_samples, ciphertext_times, modulus, INITIAL_SAMPLES, &state, interactions);
    calc_ciphertext_monts(ciphertext_monts, ciphertext_samples, INITIAL_SAMPLES, rho_sq, modulus_limbs, omega, modulus, base);
    calc_m_temps_init(m_temps, ciphertext_monts, INITIAL_SAMPLES, rho_sq, modulus_limbs, omega, modulus, base);

    for (int i = 0; i < INITIAL_SAMPLES; i++) {
        gmp_printf("%Zd\n\n%Zd\n\n%Zd\n\n\n", ciphertext_samples[i], ciphertext_monts[i], m_temps[i]);
    }

    // // TODO: Change the condition
    for (int i = 0; i < INITIAL_SAMPLES; i++) mpz_clears(ciphertext_samples[i], ciphertext_monts[i], m_temps[i], NULL);
}

void attack(const char *config_file) {
    mpz_t public_exponent, private_exponent, modulus, base, omega, rho_sq;
    mpz_inits(public_exponent, private_exponent, modulus, base, omega, rho_sq, NULL);
    int modulus_limbs, interactions = 0;
    
    get_params(config_file, &public_exponent, &modulus);
    calc_params(&base, &omega, &rho_sq, &public_exponent, &modulus, &modulus_limbs);
    calc_private_exponent(&private_exponent, &public_exponent, &modulus, &modulus_limbs, &omega, &rho_sq, &base, &interactions);

    // mpz_clears(public_exponent, modulus, base, omega, rho_sq, NULL);
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