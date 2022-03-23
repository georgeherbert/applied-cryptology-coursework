#include "attack.h"

#define BUFFER_SIZE (80)
#define TRACES (16)

pid_t pid = 0;

int target_raw[2];
int attack_raw[2];

FILE* target_out = NULL;
FILE* target_in = NULL;

unsigned char HAMMING_WEIGHT_S_BOX[256] = {
    4, 5, 6, 6, 5, 5, 6, 4, 2, 1, 5, 4, 7, 6, 5, 5,
    4, 2, 4, 6, 6, 4, 4, 4, 5, 4, 3, 6, 4, 3, 4, 2,
    6, 7, 4, 3, 4, 6, 7, 4, 3, 4, 5, 5, 4, 4, 3, 3,
    1, 5, 3, 4, 2, 4, 2, 4, 3, 2, 1, 4, 6, 4, 4, 5,
    2, 3, 3, 3, 4, 5, 4, 2, 3, 5, 5, 5, 3, 5, 5, 2,
    4, 4, 0, 6, 1, 6, 4, 5, 4, 5, 6, 4, 3, 3, 3, 6,
    3, 7, 4, 7, 3, 4, 4, 3, 3, 6, 1, 7, 2, 4, 6, 3,
    3, 4, 1, 5, 3, 5, 3, 6, 5, 5, 5, 2, 1, 8, 6, 4,
    5, 2, 3, 5, 6, 5, 2, 4, 3, 5, 6, 5, 3, 5, 3, 5,
    2, 2, 5, 5, 2, 3, 2, 2, 3, 6, 4, 2, 6, 5, 3, 6,
    3, 3, 4, 2, 3, 2, 2, 4, 3, 5, 4, 3, 3, 4, 4, 5,
    6, 3, 5, 5, 4, 5, 4, 4, 4, 4, 5, 5, 4, 5, 5, 1,
    5, 4, 3, 4, 3, 4, 4, 4, 4, 6, 4, 5, 4, 6, 4, 3,
    3, 5, 5, 4, 2, 2, 6, 3, 3, 4, 5, 5, 3, 3, 4, 5,
    4, 5, 3, 2, 4, 5, 4, 3, 5, 4, 4, 5, 5, 4, 2, 7,
    3, 3, 3, 3, 7, 5, 2, 3, 2, 4, 4, 4, 3, 3, 6, 3
};

typedef struct {
    unsigned char interactions;
} params;

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

void interact(mpz_t* tweak, mpz_t* plaintext, params* params, unsigned char trace_start[5000], unsigned char trace_end[5000]) {
    params->interactions += 1;

    fprintf(target_in, "0\n");
    gmp_fprintf(target_in, "10:%032ZX\n", *tweak);
    fflush(target_in);

    int trace_length;
    fscanf(target_out, "%d,", &trace_length);

    unsigned char trace[trace_length];
    for (int i = 0; i < trace_length - 1; i++) {
        fscanf(target_out, "%hhu,", &trace[i]);
    }
    fscanf(target_out, "%hhu\n", &trace[trace_length - 1]);

    for (int i = 0; i < 5000; i++) {
        trace_start[i] = trace[i + 1000];
        trace_end[i] = trace[i + (trace_length - 6000)];
    }

    int plaintext_length;
    fscanf(target_out, "%x:", &plaintext_length);
    gmp_fscanf(target_out, "%Zx", plaintext); // FIX THIS 
}

void get_traces(mpz_t tweaks[TRACES], unsigned char traces_start[TRACES][5000], unsigned char traces_end[TRACES][5000], mpz_t plaintexts[TRACES], params* params) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    params->interactions = 0;

    for (int i = 0; i < TRACES; i++) {
        mpz_init(tweaks[i]);
        mpz_init(plaintexts[i]);

        mpz_urandomb(tweaks[i], state, 128);
        interact(&tweaks[i], &plaintexts[i], params, traces_start[i], traces_end[i]);
    }
}

unsigned char extract_byte(mpz_t* num, unsigned char byte) {
    mpz_t temp;
    mpz_init(temp);
    mpz_fdiv_q_2exp(temp, *num, byte * 8);
    mp_limb_t least_significant_limb = mpz_getlimbn(temp, 0);
    return (unsigned char) least_significant_limb & 0xFF;
}

double pearsons(unsigned char x[TRACES], unsigned char y[TRACES]) {
    long long int sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_x_sq = 0.0, sum_y_sq = 0.0;
    for (int i = 0; i < TRACES; i++) {
        sum_x += x[i];
        sum_y += y[i];
        sum_xy += x[i] * y[i];
        sum_x_sq += x[i] * x[i];
        sum_y_sq += y[i] * y[i];
    }

    long long int numerator = TRACES * sum_xy - sum_x * sum_y;
    double denominator = (sqrt(TRACES * sum_x_sq - sum_x * sum_x) * sqrt(TRACES * sum_y_sq - sum_y * sum_y));

    double correlation = (double) numerator / denominator;

    // printf("%f %llu %f\n", correlation, numerator, denominator);
    return correlation;
}

unsigned char calc_byte(int byte, mpz_t tweaks_pps[TRACES], unsigned char traces[TRACES][5000]) {
    unsigned char byte_guess = 0;
    double max_correlation = 0;
    for (unsigned int i = 0; i < 256; i++) {
        unsigned char hamming_matrix_column[TRACES];
        for (int j = 0; j < TRACES; j++) {
            hamming_matrix_column[j] = HAMMING_WEIGHT_S_BOX[extract_byte(&(tweaks_pps[j]), byte) ^ (unsigned char) i];
        }
        for (int j = 0; j < 5000; j++) {
            unsigned char traces_column[TRACES];
            for (int k = 0; k < TRACES; k++) {
                traces_column[k] = traces[k][j];
            }
            double correlation = pearsons(traces_column, hamming_matrix_column);
            if (correlation > max_correlation) {
                max_correlation = correlation;
                byte_guess = i;
            }
            // printf("%d %f %f\n", i, max_correlation, correlation);
        }
    }
    // printf("%hhu %f\n", byte_guess, max_correlation);
    return byte_guess;
}

void calc_key(mpz_t* key, unsigned char key_2_bytes[16], mpz_t tweaks_pps[TRACES], unsigned char traces[TRACES][5000]) {
    mpz_t key_bytes[16], temp, temp_2;
    mpz_inits(*key, temp, temp_2, NULL);

    #pragma omp parallel for num_threads(16)
    for (int i = 0; i < 16; i++) {
        mpz_init(key_bytes[i]);
        unsigned char next_byte = calc_byte(i, tweaks_pps, traces);
        if (key_2_bytes != NULL) key_2_bytes[15 - i] = next_byte;
        mpz_set_ui(key_bytes[i], (unsigned long int) next_byte);
    }

    mpz_set_ui(temp, 1);
    for (int i = 0; i < 16; i++) {
        mpz_mul(temp_2, key_bytes[i], temp);
        mpz_add(*key, *key, temp_2);
        mpz_mul_ui(temp, temp, 256);
    }
}

void mpz_t_to_bytes(mpz_t* tweak, unsigned char* tweak_bytes) {
    size_t size;
    mpz_export(tweak_bytes, &size, 1, sizeof(char), -1, 0, *tweak);
    int to_shift = 16 - size;
    for (int i = 15; i >= to_shift; i--) tweak_bytes[i] = tweak_bytes[i - to_shift];
    for (int i = 0; i < to_shift; i++) tweak_bytes[i] = 0;
}

void calc_ts(unsigned char key_2_bytes[16], mpz_t tweaks[TRACES], mpz_t ts[TRACES]) {
    AES_KEY rk;
    AES_set_encrypt_key(key_2_bytes, 128, &rk);
    for (int i = 0; i < TRACES; i++) {
        unsigned char tweak_bytes[16], encrypted_bytes[16];
        mpz_t_to_bytes(&tweaks[i], tweak_bytes);
        AES_encrypt(tweak_bytes, encrypted_bytes, &rk);
        mpz_import(ts[i], 16, 1, sizeof(char), -1, 0, encrypted_bytes);
    }
}

void calc_pps(mpz_t plaintexts[TRACES], mpz_t ts[TRACES], mpz_t pps[TRACES]) {
    for (int i = 0; i < TRACES; i++) {
        mpz_init(pps[i]);
        mpz_xor(pps[i], plaintexts[i], ts[i]);
    }
}

// The main attack
void attack(const char *config_file) {
    mpz_t tweaks[TRACES], plaintexts[TRACES], ts[TRACES], pps[TRACES], key, key_1, key_2;
    unsigned char traces_start[TRACES][5000], traces_end[TRACES][5000], key_2_bytes[16];
    params params;

    get_traces(tweaks, traces_start, traces_end, plaintexts, &params);

    calc_key(&key_2, key_2_bytes, tweaks, traces_start);
    gmp_printf("Key 2: %ZX\n", key_2);

    calc_ts(key_2_bytes, tweaks, ts);
    calc_pps(plaintexts, ts, pps);

    calc_key(&key_1, NULL, pps, traces_end);
    gmp_printf("Key 1: %ZX\n\n", key_1);

    mpz_mul_2exp(key, key_1, 128);
    mpz_add(key, key, key_2);
    gmp_printf("Key: %064ZX\n", key);
    printf("Interactions: %d\n", params.interactions);
}
 
// Initialises the target variables and starts the attack
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