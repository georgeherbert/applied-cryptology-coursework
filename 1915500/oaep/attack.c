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
    char *label_hex;
    long int label_size;
    mpz_t ciphertext;
    long int ciphertext_size;
    char *ciphertext_size_hex;
    mpz_t b;
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

void get_params(char config_file[], params* params) {
    FILE *file = fopen(config_file, "r");
    char modulus_hex[1024], public_exponent_hex[1024], label_hex[1024], ciphertext_hex[1024];
    char *label_hex_split, *ciphertext_hex_split;
    char *search = ":";

    fgets(modulus_hex, sizeof(modulus_hex), file);
    fgets(public_exponent_hex, sizeof(public_exponent_hex), file);
    fgets(label_hex, sizeof(label_hex), file);
    fgets(ciphertext_hex, sizeof(ciphertext_hex), file);

    mpz_inits(params->modulus, params->public_exponent, params->label, params->ciphertext, params->b, NULL);

    mpz_set_str(params->modulus, modulus_hex, 16);
    mpz_set_str(params->public_exponent, public_exponent_hex, 16);

    label_hex[strcspn(label_hex, "\n")] = 0;
    params->label_hex = malloc(strlen(label_hex) + 1);
    strcpy(params->label_hex, label_hex);
    label_hex_split = strtok(label_hex, search);
    params->label_size = strtol(label_hex_split, NULL, 16);
    label_hex_split = strtok(NULL, search);
    mpz_set_str(params->label, label_hex_split, 16);

    ciphertext_hex_split = strtok(ciphertext_hex, search);
    params->ciphertext_size_hex = malloc(strlen(ciphertext_hex_split) + 1);
    strcpy(params->ciphertext_size_hex, ciphertext_hex_split);
    params->ciphertext_size = strtol(ciphertext_hex_split, NULL, 16);
    ciphertext_hex_split = strtok(NULL, search);
    mpz_set_str(params->ciphertext, ciphertext_hex_split, 16);

    mpz_ui_pow_ui(params->b, 2, 8 * (params->ciphertext_size - 1));
    
    fclose(file);
}

void interact(int* error_code, const char* value, params* params) {
    // printf("%s\n", params->label_hex);
    // printf("%s:%s\n", params->ciphertext_size_hex, value);
    fprintf(target_in, "%s\n", params->label_hex);
    fprintf(target_in, "%s:%s\n", params->ciphertext_size_hex, value);
    fflush(target_in);
    if (1 != fscanf(target_out, "%d", error_code)) abort();
}

void prepend_zeros(char *dest, const char *src, int width) {
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

    char value_hex[params->ciphertext_size * 2 + 1];
    prepend_zeros(value_hex, mpz_get_str(NULL, 16, value), params->ciphertext_size * 2);

    int error_code;
    interact(&error_code, value_hex, params);
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

void mpz_t_to_bytes(params *params, mpz_t* encoded_message, unsigned char* encoded_message_hex) {
    size_t size;
    mpz_export(encoded_message_hex, &size, 1, sizeof(char), -1, 0, *encoded_message);

    int to_shift = params->ciphertext_size - size;
    for (int i = params->ciphertext_size - 1; i >= to_shift; i--) {
        encoded_message_hex[i] = encoded_message_hex[i - to_shift];
    }
    for (int i = 0; i < to_shift; i++) {
        encoded_message_hex[i] = 0;
    }
}

void mgf1(unsigned char* input, int input_length, unsigned char* output, int output_length) {
    unsigned char temp[input_length + 4];

    int counter = 0;
    for (int i = 0; i < output_length; i += 20) {
        memcpy(temp, input, input_length);
        memcpy(temp + input_length, &counter, 4);

        SHA1(temp, input_length + 4, output + i);
        counter++;
    }
}

void xor(unsigned char* x, unsigned char* y, unsigned char* output, int length) {
    for (int i = 0; i < length; i++) {
        output[i] = x[i] ^ y[i];
    }
}

void decode(params* params, mpz_t* encoded_message) {
    unsigned char encoded_message_hex[params->ciphertext_size];
    mpz_t_to_bytes(params, encoded_message, encoded_message_hex);

    unsigned char masked_seed[20], masked_db[params->ciphertext_size - 21], seed_mask[20], db_mask[params->ciphertext_size - 21], seed[params->ciphertext_size - 21], db[params->ciphertext_size - 21], lhash[20], lhash_[20];
    memcpy(masked_seed, encoded_message_hex + 1, 20);
    memcpy(masked_db, encoded_message_hex + 21, params->ciphertext_size - 21);
    printf("\nmasked_db: ");
    for (int i = 0; i < params->ciphertext_size - 21; i++) {
        printf("%02x", masked_db[i]);
    }

    mgf1(masked_db, params->ciphertext_size - 21, seed_mask, 20);
    printf("\nmasked_db: ");
    for (int i = 0; i < params->ciphertext_size - 21; i++) {
        printf("%02x", masked_db[i]);
    }
    xor(masked_seed, seed_mask, seed, 20);
    printf("\nmasked_db: ");
    for (int i = 0; i < params->ciphertext_size - 21; i++) {
        printf("%02x", masked_db[i]);
    }
    mgf1(seed, 20, db_mask, params->ciphertext_size - 21);
    printf("\nmasked_db: ");
    for (int i = 0; i < params->ciphertext_size - 21; i++) {
        printf("%02x", masked_db[i]);
    }
    xor(masked_db, db_mask, db, params->ciphertext_size - 21);
    printf("\nmasked_db: ");
    for (int i = 0; i < params->ciphertext_size - 21; i++) {
        printf("%02x", masked_db[i]);
    }

    unsigned char label_bytes[params->label_size];
    mpz_export(label_bytes, NULL, 1, sizeof(char), -1, 0, params->label);
    SHA1(label_bytes, params->label_size, lhash);
    memcpy(lhash_, db, 20);

    // printf("\encoded_message: ");
    // for (int i = 0; i < 128; i++) {
    //     printf("%02x", encoded_message_hex[i]);
    // }
    // printf("\nmasked_seed: ");
    // for (int i = 0; i < 20; i++) {
    //     printf("%02x", masked_seed[i]);
    // }
    printf("\nmasked_db: ");
    for (int i = 0; i < params->ciphertext_size - 21; i++) {
        printf("%02x", masked_db[i]);
    }
    // printf("\nseed_mask: ");
    // for (int i = 0; i < 20; i++) {
    //     printf("%02x", seed_mask[i]);
    // }
    // printf("\ndb_mask: ");
    // for (int i = 0; i < params->ciphertext_size - 21; i++) {
    //     printf("%02x", db_mask[i]);
    // }
    // printf("\nseed: ");
    // for (int i = 0; i < 20; i++) {
    //     printf("%02x", seed[i]);
    // }
    // printf("\ndb: ");
    // for (int i = 0; i < params->ciphertext_size - 21; i++) {
    //     printf("%02x", db[i]);
    // }
    // printf("\nLabel: ");
    // for (int i = 0; i < params->label_size; i++) {
    //     printf("%02x", label_bytes[i]);
    // }
    // printf("\nlhash: ");
    // for (int i = 0; i < 20; i++) {
    //     printf("%02x", lhash[i]);
    // }
    // printf("\nlhash_: ");
    // for (int i = 0; i < 20; i++) {
    //     printf("%02x", lhash_[i]);
    // }

}

void attack(char config_file[]) {
    params params;
    mpz_t f_1, f_2, encoded_message, message;
    
    get_params(config_file, &params);

    // gmp_printf("%Zd\n\n", params.modulus);
    // gmp_printf("%Zd\n\n", params.public_exponent);
    // gmp_printf("%Zd\n\n", params.label);
    // gmp_printf("%s\n\n", params.label_hex);
    // printf("%ld\n\n", params.label_size);
    // gmp_printf("%Zd\n\n", params.ciphertext);
    // printf("%ld\n\n", params.ciphertext_size);
    // printf("%s\n\n", params.ciphertext_size_hex);
    // gmp_printf("%Zd\n\n", params.b);

    step_1(&params, &f_1);
    gmp_printf("f_1: %Zd\n", f_1);
    step_2(&params, &f_1, &f_2);
    gmp_printf("f_2: %Zd\n", f_2);
    step_3(&params, &f_2, &encoded_message);
    gmp_printf("Encoded message: %Zd\n", encoded_message);
    decode(&params, &encoded_message);
    gmp_printf("Message: %Zd\n", message);
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

// TODO: Add leading zeros if value is not 128 bytes