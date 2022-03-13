#include "attack.h"

#define BUFFER_SIZE (80)

pid_t pid = 0;

int target_raw[2];
int attack_raw[2];

FILE* target_out = NULL;
FILE* target_in = NULL;

void interact(int* t, int* r, const char* G) {
    // Send G to attack target.
    fprintf (target_in, "%s\n", G); fflush(target_in);
    // Receive ( t, r ) from attack target.
    if (1 != fscanf(target_out, "%d", t)) abort();
    if (1 != fscanf( target_out, "%d", r)) abort();
}

void get_attack_params(char config_file[], mpz_t* modulus, mpz_t* public_exponent, mpz_t* label, mpz_t* ciphertext, long int* label_size, long int* ciphertext_size) {
    FILE *file = fopen(config_file, "r");
    char modulus_hex[1024], public_exponent_hex[1024], label_hex[1024], ciphertext_hex[1024];
    char *label_hex_split, *ciphertext_hex_split;
    char *search = ":";

    fgets(modulus_hex, sizeof(modulus_hex), file);
    fgets(public_exponent_hex, sizeof(public_exponent_hex), file);
    fgets(label_hex, sizeof(label_hex), file);
    fgets(ciphertext_hex, sizeof(ciphertext_hex), file);

    mpz_set_str(*modulus, modulus_hex, 16);
    mpz_set_str(*public_exponent, public_exponent_hex, 16);

    label_hex_split = strtok(label_hex, search);
    *label_size = strtol(label_hex_split, NULL, 16);
    label_hex_split = strtok(NULL, search);
    mpz_set_str(*label, label_hex_split, 16);

    ciphertext_hex_split = strtok(ciphertext_hex, search);
    *ciphertext_size = strtol(ciphertext_hex_split, NULL, 16);
    ciphertext_hex_split = strtok(NULL, search);
    mpz_set_str(*ciphertext, ciphertext_hex_split, 16);
    
    fclose(file);
}

void attack(char config_file[]) {
    mpz_t modulus, public_exponent, label, ciphertext;
    mpz_init(modulus); mpz_init(public_exponent); mpz_init(label); mpz_init(ciphertext);
    long int label_size, ciphertext_size;
    
    get_attack_params(config_file, &modulus, &public_exponent, &label, &ciphertext, &label_size, &ciphertext_size);

    gmp_printf("%Zd\n\n", modulus);
    gmp_printf("%Zd\n\n", public_exponent);
    gmp_printf("%Zd\n\n", label);
    gmp_printf("%Zd\n\n", ciphertext);
    printf("%ld\n\n", label_size);
    printf("%ld\n\n", ciphertext_size);

    // // Select a hard-coded guess ...
    // char* G = "guess";
    // int t;
    // int r;
    // // ... then interact with the attack target.
    // interact(&t, &r, G);
    // // Print all of the inputs and outputs.
    // printf("G = %s\n", G);
    // printf("t = %d\n", t);
    // printf("r = %d\n", r);
}

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
