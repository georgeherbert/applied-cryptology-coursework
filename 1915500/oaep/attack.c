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
    mpz_t ciphertext;
    long int label_size;
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

    mpz_set_str(params->modulus, modulus_hex, 16);
    mpz_set_str(params->public_exponent, public_exponent_hex, 16);

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

void interact(int* error_code, const char* value) {
    fprintf (target_in, "%s\n", value); fflush(target_in);
    if (1 != fscanf(target_out, "%d", error_code)) abort();
}

int send_to_oracle(mpz_t* f_num, params* params) {
    mpz_t value;
    mpz_init(value);
    mpz_powm(value, *f_num, params->public_exponent, params->modulus);
    mpz_mul(value, value, params->ciphertext);
    mpz_mod(value, value, params->modulus);

    return 1;
}

void step_1(params* params, mpz_t* f_1) {
    mpz_init_set_ui(*f_1, 2);
    while (send_to_oracle(f_1, params) != 1) {
        mpz_mul_ui(*f_1, *f_1, 2);
    }
}

void attack(char config_file[]) {
    params params;
    mpz_t f_1, f_2;
    mpz_inits(params.modulus, params.public_exponent, params.label, params.ciphertext, params.b, NULL);
    
    get_params(config_file, &params);

    gmp_printf("%Zd\n\n", params.modulus);
    gmp_printf("%Zd\n\n", params.public_exponent);
    gmp_printf("%Zd\n\n", params.label);
    gmp_printf("%Zd\n\n", params.ciphertext);
    printf("%ld\n\n", params.label_size);
    printf("%ld\n\n", params.ciphertext_size);
    printf("%s\n\n", params.ciphertext_size_hex);
    gmp_printf("%Zd\n\n", params.b);

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
