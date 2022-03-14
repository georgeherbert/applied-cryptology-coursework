#include "attack.h"

#define BUFFER_SIZE (80)

pid_t pid = 0;

int target_raw[2];
int attack_raw[2];

FILE* target_out = NULL;
FILE* target_in = NULL;

typedef struct {
    mpz_t modulus;
    mpz_t public_exponent;
    mpz_t label;
    char *label_bytes;
    unsigned long long int label_size;
    mpz_t ciphertext;
    unsigned long long int ciphertext_size;
    char *ciphertext_size_bytes;
    mpz_t b;
    unsigned long long int interactions;
} params;

void cleanup(int s){
    fclose(target_in);
    fclose(target_out);
    close(target_raw[0]); 
    close(target_raw[1]); 
    close(attack_raw[0]); 
    close(attack_raw[1]); 
    if (pid > 0) kill(pid, SIGKILL);
    exit(1); 
}

void get_params(const char *config_file, params* params) {
    FILE *file = fopen(config_file, "r");
    char modulus_bytes[65536], public_exponent_bytes[65536], label_bytes[65536], ciphertext_bytes[65536];
    char *label_bytes_split, *ciphertext_bytes_split;
    char *search = ":";

    fgets(modulus_bytes, sizeof(modulus_bytes), file);
    fgets(public_exponent_bytes, sizeof(public_exponent_bytes), file);
    fgets(label_bytes, sizeof(label_bytes), file);
    fgets(ciphertext_bytes, sizeof(ciphertext_bytes), file);

    mpz_inits(params->modulus, params->public_exponent, params->label, params->ciphertext, params->b, NULL);

    mpz_set_str(params->modulus, modulus_bytes, 16);
    mpz_set_str(params->public_exponent, public_exponent_bytes, 16);

    label_bytes[strcspn(label_bytes, "\n")] = 0;
    params->label_bytes = malloc(strlen(label_bytes) + 1);
    strcpy(params->label_bytes, label_bytes);
    label_bytes_split = strtok(label_bytes, search);
    params->label_size = strtol(label_bytes_split, NULL, 16);
    label_bytes_split = strtok(NULL, search);
    mpz_set_str(params->label, label_bytes_split, 16);

    ciphertext_bytes_split = strtok(ciphertext_bytes, search);
    params->ciphertext_size_bytes = malloc(strlen(ciphertext_bytes_split) + 1);
    strcpy(params->ciphertext_size_bytes, ciphertext_bytes_split);
    params->ciphertext_size = strtol(ciphertext_bytes_split, NULL, 16);
    ciphertext_bytes_split = strtok(NULL, search);
    mpz_set_str(params->ciphertext, ciphertext_bytes_split, 16);

    mpz_ui_pow_ui(params->b, 2, 8 * (params->ciphertext_size - 1));
    
    fclose(file);
}

void interact(int* error_code, const char* value, params* params) {
    params->interactions += 1;
    fprintf(target_in, "%s\n", params->label_bytes);
    fprintf(target_in, "%s:%s\n", params->ciphertext_size_bytes, value);
    fflush(target_in);
    fscanf(target_out, "%d", error_code);
}

void prepend_zeros(char *dest, const char *src, const unsigned long long int width) {
    size_t len = strlen(src);
    if (len >= width) strcpy(dest, src);
    else sprintf(dest, "%0*d%s", (int) (width - len), 0, src);
}

int send_to_oracle(mpz_t* f_num, params* params) {
    mpz_t value;
    mpz_init(value);
    mpz_powm(value, *f_num, params->public_exponent, params->modulus);
    mpz_mul(value, value, params->ciphertext);
    mpz_mod(value, value, params->modulus);

    char value_bytes[params->ciphertext_size * 2 + 1];
    prepend_zeros(value_bytes, mpz_get_str(NULL, 16, value), params->ciphertext_size * 2);

    int error_code;
    interact(&error_code, value_bytes, params);
    // printf("Error code: %d\n", error_code);
    return error_code;
}

void step_1(params* params, mpz_t* f_1) {
    mpz_init_set_ui(*f_1, 2);
    while (send_to_oracle(f_1, params) != 1) {
        mpz_mul_ui(*f_1, *f_1, 2);
    }
}

void step_2(params* params, mpz_t* f_1, mpz_t* f_2) {
    mpz_t temp, temp_2;
    mpz_inits(*f_2, temp, temp_2, NULL);
    mpz_add(temp, params->modulus, params->b);
    mpz_fdiv_q(temp, temp, params->b);
    mpz_fdiv_q_ui(temp_2, *f_1, 2);
    mpz_mul(*f_2, temp, temp_2);
    while (send_to_oracle(f_2, params) != 2) {
        mpz_add(*f_2, *f_2, temp_2);
        // gmp_printf("f_2: %Zd\n", *f_2);
    }
}

void step_3(params* params, mpz_t* f_2, mpz_t* encoded_message) {
    mpz_t message_min, message_max, f_tmp, i, f_3, temp, temp_2;
    mpz_inits(*encoded_message, message_min, message_max, f_tmp, i, f_3, temp, temp_2, NULL);
    
    mpz_cdiv_q(message_min, params->modulus, *f_2);
    mpz_add(temp, params->modulus, params->b);
    mpz_fdiv_q(message_max, temp, *f_2);

    while (mpz_cmp(message_min, message_max)) {
        // gmp_printf("%Zd %Zd\n", message_min, message_max);
        mpz_mul_ui(temp, params->b, 2);
        mpz_sub(temp_2, message_max, message_min);
        mpz_fdiv_q(f_tmp, temp, temp_2);

        mpz_mul(temp, f_tmp, message_min);
        mpz_fdiv_q(i, temp, params->modulus);

        mpz_mul(temp, i, params->modulus);
        mpz_cdiv_q(f_3, temp, message_min);

        mpz_add(temp, temp, params->b);
        if (send_to_oracle(&f_3, params) == 1) {
            mpz_cdiv_q(message_min, temp, f_3);
        }
        else {
            mpz_fdiv_q(message_max, temp, f_3);
        }
    }
    mpz_set(*encoded_message, message_min);
}

void mpz_t_to_bytes(params *params, mpz_t* encoded_message, unsigned char* encoded_message_bytes) {
    size_t size;
    mpz_export(encoded_message_bytes, &size, 1, sizeof(char), -1, 0, *encoded_message);

    const unsigned long long to_shift = params->ciphertext_size - size;
    for (unsigned long long int i = params->ciphertext_size - 1; i >= to_shift; i--) {
        encoded_message_bytes[i] = encoded_message_bytes[i - to_shift];
    }
    for (unsigned long long int i = 0; i < to_shift; i++) {
        encoded_message_bytes[i] = 0;
    }
}

void mgf1(unsigned char* input, unsigned char* output, const unsigned long long int input_length, const unsigned long long int output_length) {
    unsigned char temp[input_length + 4];

    unsigned long long int size_of_temp_2;
    unsigned long long int remainder = output_length % 20;
    if (remainder == 0) size_of_temp_2 = output_length;
    else size_of_temp_2 = output_length + 20 - remainder;
    unsigned char temp_2[size_of_temp_2];

    memcpy(temp, input, input_length);
    for (unsigned long long int counter = 0; counter <= ((output_length - 1) / 20); counter += 1) {
        unsigned char counter_byte_1 = counter >> 24 & 0xFF;
        unsigned char counter_byte_2 = counter >> 16 & 0xFF;
        unsigned char counter_byte_3 = counter >> 8 & 0xFF;
        unsigned char counter_byte_4 = counter & 0xFF;

        memcpy(temp + input_length, &counter_byte_1, 1);
        memcpy(temp + input_length + 1, &counter_byte_2, 1);
        memcpy(temp + input_length + 2, &counter_byte_3, 1);
        memcpy(temp + input_length + 3, &counter_byte_4, 1);

        SHA1(temp, input_length + 4, temp_2 + counter * 20);
    }
    memcpy(output, temp_2, output_length);
}

void xor(const unsigned char* src_x, const unsigned char* src_y, unsigned char* dest, const unsigned long long int size) {
    for (unsigned long long int i = 0; i < size; i++) {
        dest[i] = src_x[i] ^ src_y[i];
    }
}

int find_message_index(const unsigned char* db, const unsigned long long int size) {
    for (int i = 0; i < size; i++) {
        if (db[i] == 0x01) return i + 1;
    }
    return -1;
}

void decode(params* params, mpz_t* encoded_message, mpz_t* message) {
    unsigned char encoded_message_bytes[params->ciphertext_size];
    mpz_t_to_bytes(params, encoded_message, encoded_message_bytes);

    const unsigned long long int remainder_size = params->ciphertext_size - 21;

    unsigned char masked_seed[20], seed_mask[20], seed[20];
    unsigned char masked_db[remainder_size], db_mask[remainder_size], db[remainder_size];
    unsigned char lhash[20], lhash_[20];

    memcpy(masked_seed, encoded_message_bytes + 1, 20);
    memcpy(masked_db, encoded_message_bytes + 21, remainder_size);

    mgf1(masked_db, seed_mask, remainder_size, 20);
    xor(masked_seed, seed_mask, seed, 20);
    mgf1(seed, db_mask, 20, remainder_size);
    xor(masked_db, db_mask, db, remainder_size);

    unsigned char label_bytes[params->label_size];
    mpz_export(label_bytes, NULL, 1, sizeof(char), -1, 0, params->label);
    SHA1(label_bytes, params->label_size, lhash);
    memcpy(lhash_, db, 20);

    const int message_index = find_message_index(db, remainder_size);

    const int message_size = remainder_size - message_index;
    unsigned char message_bytes[message_size];
    memcpy(message_bytes, db + message_index, message_size);

    mpz_init(*message);
    mpz_import(*message, message_size, 1, sizeof(char), -1, 0, message_bytes);
}

void attack(const char *config_file) {
    clock_t tic = clock();
    params params;
    mpz_t f_1, f_2, encoded_message, message;

    params.interactions = 0;
    get_params(config_file, &params);

    step_1(&params, &f_1);
    gmp_printf("f_1 (base 10): %Zd\n", f_1);
    step_2(&params, &f_1, &f_2);
    gmp_printf("f_2 (base 10): %Zd\n", f_2);
    step_3(&params, &f_2, &encoded_message);
    gmp_printf("Encoded message (base 10): %Zd\n\n", encoded_message);
    decode(&params, &encoded_message, &message);
    
    clock_t toc = clock();
    printf("Attack complete\nTime taken: %.2f seconds.\n", ((double) toc - tic) / CLOCKS_PER_SEC);
    gmp_printf("Target material (base 10): %Zd\n", message);
    printf("Interactions (base 10): %llu\n", params.interactions);
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