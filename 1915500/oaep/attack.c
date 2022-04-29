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
    unsigned int label_size;
    mpz_t ciphertext;
    unsigned int ciphertext_size;
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

// Gets the parameters needed for the attack
void get_params(const char *config_file, params* params) {
    FILE *file = fopen(config_file, "r");

    gmp_fscanf(file, "%Zx\n", params->modulus);
    gmp_fscanf(file, "%Zx\n", params->public_exponent);
    fscanf(file, "%x:", &params->label_size);
    gmp_fscanf(file, "%Zx\n", params->label);
    fscanf(file, "%x:", &params->ciphertext_size);
    gmp_fscanf(file, "%Zx\n", params->ciphertext);

    mpz_ui_pow_ui(params->b, 2, 8 * (params->ciphertext_size - 1));

    fclose(file);
}

// Interacts with the device
void interact(int* error_code, mpz_t *value, params* params) {
    params->interactions += 1;
    gmp_fprintf(target_in, "%x:%Z0*x\n", params->label_size, params->label_size * 2, params->label);
    gmp_fprintf(target_in, "%x:%0*Zx\n", params->ciphertext_size, params->ciphertext_size * 2, *value);
    fflush(target_in);
    fscanf(target_out, "%d", error_code);
}

// Prepends zeros to src
void prepend_zeros(char *dest, const char *src, const unsigned long long int width) {
    size_t len = strlen(src);
    if (len >= width) strcpy(dest, src);
    else sprintf(dest, "%0*d%s", (int) (width - len), 0, src);
}

// Processes f_num and sends it to the oracle
int send_to_oracle(mpz_t* f_num, params* params) {
    mpz_t value;
    mpz_init(value);
    mpz_powm(value, *f_num, params->public_exponent, params->modulus);
    mpz_mul(value, value, params->ciphertext);
    mpz_mod(value, value, params->modulus);

    int error_code;
    interact(&error_code, &value, params);
    // printf("Error code: %d\n", error_code);
    return error_code;
}

// Step 1 of the attack
void step_1(params* params, mpz_t* f_1) {
    mpz_init_set_ui(*f_1, 2);
    while (send_to_oracle(f_1, params) != 1) {
        mpz_mul_ui(*f_1, *f_1, 2);
    }
}

// Step 2 of the attack
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

// Step 3 of the attack
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

// Converts the mpz_t encoded_encoded message into an array of bytes of the correct length
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

// Implements the MGF1 masg generation function
void mgf1(unsigned char* input, unsigned char* output, const unsigned long long int input_length, const unsigned long long int output_length) {
    // temp stores the bytes of each iteration before it is hashed
    unsigned char temp[input_length + 4];

    // temp_2 stores the full output before it is truncated
    unsigned long long int size_of_temp_2;
    unsigned long long int remainder = output_length % 20;
    if (remainder == 0) size_of_temp_2 = output_length;
    else size_of_temp_2 = output_length + 20 - remainder;
    unsigned char temp_2[size_of_temp_2];

    memcpy(temp, input, input_length);
    for (unsigned long long int counter = 0; counter <= ((output_length - 1) / 20); counter += 1) {
        // Adds the counter
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
    // Only the leading l octets of temp_2 are required
    memcpy(output, temp_2, output_length);
}

// XORs two byte arrays
void xor(const unsigned char* src_x, const unsigned char* src_y, unsigned char* dest, const unsigned long long int size) {
    for (unsigned long long int i = 0; i < size; i++) {
        dest[i] = src_x[i] ^ src_y[i];
    }
}

// Finds the index of the 0x01 octet in db
int find_message_index(const unsigned char* db, const unsigned long long int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (db[i] == 0x01) break;
    }
    return i + 1;
}

// Decodes the encoded message
void decode(params* params, mpz_t* encoded_message, mpz_t* message) {
    unsigned char encoded_message_bytes[params->ciphertext_size];
    mpz_t_to_bytes(params, encoded_message, encoded_message_bytes);

    const unsigned long long int remainder_size = params->ciphertext_size - 21;

    unsigned char masked_seed[20], seed_mask[20], seed[20];
    unsigned char masked_db[remainder_size], db_mask[remainder_size], db[remainder_size];
    unsigned char lhash[20], lhash_[20];

    // Sets the masked_seed and masked_db variables
    memcpy(masked_seed, encoded_message_bytes + 1, 20);
    memcpy(masked_db, encoded_message_bytes + 21, remainder_size);

    // Sets the seed_mask, seed, db_mask and db variables
    mgf1(masked_db, seed_mask, remainder_size, 20);
    xor(masked_seed, seed_mask, seed, 20);
    mgf1(seed, db_mask, 20, remainder_size);
    xor(masked_db, db_mask, db, remainder_size);

    // Ensures that lhash and lhash_ match (used in testing)
    unsigned char label_bytes[params->label_size];
    mpz_export(label_bytes, NULL, 1, sizeof(char), -1, 0, params->label);
    SHA1(label_bytes, params->label_size, lhash);
    memcpy(lhash_, db, 20);
    printf("%s %s\n", lhash, lhash_);

    printf("DB (base 16): ");
    for (int i = 0; i < remainder_size; i++) printf("%x", db[i]);
    printf("\n\n");

    // Extracts the message from db
    const int message_index = find_message_index(db, remainder_size);
    const int message_size = remainder_size - message_index;
    unsigned char message_bytes[message_size];
    memcpy(message_bytes, db + message_index, message_size);

    // Converts the message from an array of bytes to a mpz_t
    mpz_init(*message);
    mpz_import(*message, message_size, 1, sizeof(char), -1, 0, message_bytes);
}

// The main attack
void attack(const char *config_file) {
    clock_t tic = clock();
    params params;
    mpz_t f_1, f_2, encoded_message, message;

    mpz_inits(params.modulus, params.public_exponent, params.label, params.ciphertext, params.b, NULL);

    params.interactions = 0;
    get_params(config_file, &params);

    // The four main stages of the attack
    step_1(&params, &f_1);
    gmp_printf("f_1 (base 10): %Zd\n", f_1);
    step_2(&params, &f_1, &f_2);
    gmp_printf("f_2 (base 10): %Zd\n", f_2);
    step_3(&params, &f_2, &encoded_message);
    gmp_printf("Encoded message (base 16): %Zx\n", encoded_message);
    decode(&params, &encoded_message, &message);
    
    clock_t toc = clock();
    printf("Attack complete\nTime taken: %.2f seconds.\n", ((double) toc - tic) / CLOCKS_PER_SEC);
    gmp_printf("Target material (base 16): %Zx\n", message);
    printf("Interactions (base 10): %llu\n", params.interactions);
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