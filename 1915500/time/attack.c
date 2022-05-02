#include "attack.h"

#define BUFFER_SIZE (80)
#define WORD_LENGTH (64)
#define INITIAL_SAMPLES (1000)
#define TEST_MESSAGE (0x123456789abcdef)
#define THRESHOLD (20)

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
    for (int i = 0; i < num_samples; i++) mont_mul(&ciphertext_monts[i], &ciphertext_samples[i], rho_sq, modulus_limbs, omega, modulus, base);
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
    for (int i = 0; i < num_samples; i++) mont_exp_init(&m_temps[i], &ciphertext_monts[i], rho_sq, modulus_limbs, omega, modulus, base);
}

void calc_private_exponent_setup(mpz_t *ciphertext_samples, unsigned int *ciphertext_times, mpz_t *ciphertext_monts, mpz_t *m_temps, int num_samples, gmp_randstate_t *state, mpz_t *modulus, int *modulus_limbs, mpz_t *omega, mpz_t *rho_sq, mpz_t *base, int *interactions) {
    gen_ciphertext_samples_times(ciphertext_samples, ciphertext_times, modulus, num_samples, state, interactions);
    calc_ciphertext_monts(ciphertext_monts, ciphertext_samples, num_samples, rho_sq, modulus_limbs, omega, modulus, base);
    calc_m_temps_init(m_temps, ciphertext_monts, num_samples, rho_sq, modulus_limbs, omega, modulus, base);
}

int test_private_exponent(mpz_t *private_exponent, mpz_t *public_exponent, mpz_t *modulus, mpz_t *test_message, mpz_t *test_message_encrypted) {
    int last_digit_zero = 0, last_digit_one = 0;
    mpz_t private_exponent_zero, private_exponent_one, temp;
    mpz_inits(private_exponent_zero, private_exponent_one, temp, NULL);
    mpz_mul_ui(private_exponent_zero, *private_exponent, 2);
    mpz_add_ui(private_exponent_one, private_exponent_zero, 1);

    mpz_powm(temp, *test_message_encrypted, private_exponent_zero, *modulus);
    last_digit_zero = mpz_cmp(temp, *test_message) == 0;

    mpz_powm(temp, *test_message_encrypted, private_exponent_one, *modulus);
    last_digit_one = mpz_cmp(temp, *test_message) == 0;

    if (last_digit_zero) {
        mpz_set(*private_exponent, private_exponent_zero);
    }
    else if (last_digit_one) {
        mpz_set(*private_exponent, private_exponent_one);
    }

    mpz_clears(private_exponent_zero, private_exponent_one, temp, NULL);

    return last_digit_zero || last_digit_one;
}

void mont_exp_next(mpz_t *m_temp_result, int *reduction_result, mpz_t *m_temp, mpz_t *ciphertext_mont, int bit_set, int *modulus_limbs, mpz_t *omega, mpz_t *modulus, mpz_t *base) {
    if (bit_set) {
        mont_mul(m_temp_result, m_temp, ciphertext_mont, modulus_limbs, omega, modulus, base);
        *reduction_result = mont_mul(m_temp_result, m_temp_result, m_temp_result, modulus_limbs, omega, modulus, base);
    } 
    else {
        *reduction_result = mont_mul(m_temp_result, m_temp, m_temp, modulus_limbs, omega, modulus, base);
    }
}

double calc_m_average(unsigned int **m_array, unsigned int *m_num) {
    unsigned long long sum = 0;
    for (int i = 0; i < *m_num; i++) {
        sum += *m_array[i];
        // printf("%llu\n", sum);
    }
    // printf("\nSum: %llu\n\n\n", sum);
    double average = ((double) sum) / ((double) *m_num);
    return average;
}

void calc_m_averages(double *m_1, double *m_2, double *m_3, double *m_4, int *reductions_bit_zero, int* reductions_bit_one, unsigned int *ciphertext_times, int num_samples) {
    unsigned int **m_1_array = malloc(sizeof(unsigned int *) * num_samples);
    unsigned int **m_2_array = malloc(sizeof(unsigned int *) * num_samples);
    unsigned int **m_3_array = malloc(sizeof(unsigned int *) * num_samples);
    unsigned int **m_4_array = malloc(sizeof(unsigned int *) * num_samples);

    unsigned int m_1_num = 0, m_2_num = 0, m_3_num = 0, m_4_num = 0;

    for (int i = 0; i < num_samples; i++) {
        if (reductions_bit_zero[i]) {
            m_3_array[m_3_num] = &ciphertext_times[i];
            m_3_num++;
        }
        else {
            m_4_array[m_4_num] = &ciphertext_times[i];
            m_4_num++;
        }
    }
    for (int i = 0; i < num_samples; i++) {
        if (reductions_bit_one[i]) {
            m_1_array[m_1_num] = &ciphertext_times[i];
            m_1_num++;
        }
        else {
            m_2_array[m_2_num] = &ciphertext_times[i];
            m_2_num++;
        }
    }

    *m_1 = calc_m_average(m_1_array, &m_1_num);
    *m_2 = calc_m_average(m_2_array, &m_2_num);
    *m_3 = calc_m_average(m_3_array, &m_3_num);
    *m_4 = calc_m_average(m_4_array, &m_4_num);

    free(m_1_array);
    free(m_2_array);
    free(m_3_array);
    free(m_4_array);
}

void calc_private_exponent(mpz_t *private_exponent, mpz_t *public_exponent, mpz_t *modulus, int *modulus_limbs, mpz_t *omega, mpz_t *rho_sq, mpz_t *base, int *interactions) {
    mpz_t *ciphertext_samples = malloc(sizeof(mpz_t) * INITIAL_SAMPLES);
    unsigned int *ciphertext_times = malloc(sizeof(unsigned int) * INITIAL_SAMPLES);
    mpz_t *ciphertext_monts = malloc(sizeof(mpz_t) * INITIAL_SAMPLES);
    mpz_t *m_temps = malloc(sizeof(mpz_t) * INITIAL_SAMPLES);
    mpz_t *m_temps_bit_zero = malloc(sizeof(mpz_t) * INITIAL_SAMPLES);
    mpz_t *m_temps_bit_one = malloc(sizeof(mpz_t) * INITIAL_SAMPLES);
    int *reductions_bit_zero = malloc(sizeof(int) * INITIAL_SAMPLES);
    int *reductions_bit_one = malloc(sizeof(int) * INITIAL_SAMPLES);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    for (int i = 0; i < INITIAL_SAMPLES; i++) mpz_inits(ciphertext_monts[i], m_temps[i], m_temps_bit_zero[i], m_temps_bit_one[i], NULL);
    calc_private_exponent_setup(ciphertext_samples, ciphertext_times, ciphertext_monts, m_temps, INITIAL_SAMPLES, &state, modulus, modulus_limbs, omega, rho_sq, base, interactions);
    
    mpz_t test_message, test_message_encrypted;
    mpz_inits(test_message, test_message_encrypted, NULL);
    mpz_set_ui(test_message, TEST_MESSAGE);
    mpz_powm(test_message_encrypted, test_message, *public_exponent, *modulus);

    int num_samples = INITIAL_SAMPLES;

    mpz_set_ui(*private_exponent, 1);
    while (!test_private_exponent(private_exponent, public_exponent, modulus, &test_message, &test_message_encrypted)) {
        for (int i = 0; i < num_samples; i++) {
            mont_exp_next(&m_temps_bit_zero[i], &reductions_bit_zero[i], &m_temps[i], &ciphertext_monts[i], 0, modulus_limbs, omega, modulus, base);
            mont_exp_next(&m_temps_bit_one[i], &reductions_bit_one[i], &m_temps[i], &ciphertext_monts[i], 1, modulus_limbs, omega, modulus, base);
        }

        double m_1, m_2, m_3, m_4;
        calc_m_averages(&m_1, &m_2, &m_3, &m_4, reductions_bit_zero, reductions_bit_one, ciphertext_times, num_samples);
        double diff = fabs(m_1 - m_2) - fabs(m_3 - m_4);
        mpz_mul_ui(*private_exponent, *private_exponent, 2);

        if (diff > 0) {
            mpz_add_ui(*private_exponent, *private_exponent, 1);
            for (int i = 0; i < num_samples; i++) mpz_set(m_temps[i], m_temps_bit_one[i]);
        } else {
            for (int i = 0; i < num_samples; i++) mpz_set(m_temps[i], m_temps_bit_zero[i]);
        }
        
        if (fabs(diff) < THRESHOLD) {
            int new_num_samples = num_samples * 2;
            ciphertext_samples = realloc(ciphertext_samples, sizeof(mpz_t) * new_num_samples);
            ciphertext_times = realloc(ciphertext_times, sizeof(unsigned int) * new_num_samples);
            ciphertext_monts = realloc(ciphertext_monts, sizeof(mpz_t) * new_num_samples);
            m_temps = realloc(m_temps, sizeof(mpz_t) * new_num_samples);
            m_temps_bit_zero = realloc(m_temps_bit_zero, sizeof(mpz_t) * new_num_samples);
            m_temps_bit_one = realloc(m_temps_bit_one, sizeof(mpz_t) * new_num_samples);
            reductions_bit_zero = realloc(reductions_bit_zero, sizeof(int) * new_num_samples);
            reductions_bit_one = realloc(reductions_bit_one, sizeof(int) * new_num_samples);

            for (int i = num_samples; i < new_num_samples; i++) mpz_inits(ciphertext_monts[i], m_temps[i], m_temps_bit_zero[i], m_temps_bit_one[i], NULL);

            gen_ciphertext_samples_times(&ciphertext_samples[num_samples], &ciphertext_times[num_samples], modulus, num_samples, &state, interactions);
            calc_ciphertext_monts(ciphertext_monts, ciphertext_samples, new_num_samples, rho_sq, modulus_limbs, omega, modulus, base);
            calc_m_temps_init(m_temps, ciphertext_monts, new_num_samples, rho_sq, modulus_limbs, omega, modulus, base);

            mpz_set_ui(*private_exponent, 1);

            num_samples = new_num_samples;
        }
    }

    mpz_clears(test_message, test_message_encrypted, NULL);
    for (int i = 0; i < num_samples; i++) mpz_clears(ciphertext_samples[i], ciphertext_monts[i], m_temps[i], m_temps_bit_zero[i], m_temps_bit_one[i], NULL);
}

void attack(const char *config_file) {
    struct timeval timstr;
    gettimeofday(&timstr, NULL);
    double tic = timstr.tv_sec + (timstr.tv_usec / 1000000.0);

    mpz_t public_exponent, private_exponent, modulus, base, omega, rho_sq;
    mpz_inits(public_exponent, private_exponent, modulus, base, omega, rho_sq, NULL);
    int modulus_limbs, interactions = 0;
    
    get_params(config_file, &public_exponent, &modulus);
    calc_params(&base, &omega, &rho_sq, &public_exponent, &modulus, &modulus_limbs);
    calc_private_exponent(&private_exponent, &public_exponent, &modulus, &modulus_limbs, &omega, &rho_sq, &base, &interactions);
    
    gettimeofday(&timstr, NULL);
    double toc = timstr.tv_sec + (timstr.tv_usec / 1000000.0);

    printf("Attack time: %.2f seconds\n", toc - tic);
    gmp_printf("Target material (base 16): %Zx\n", private_exponent);
    printf("Interactions (base 10): %d\n", interactions);

    mpz_clears(public_exponent, private_exponent, modulus, omega, rho_sq, base, NULL);
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