#include "attack.h"

#define BUFFER_SIZE (80)
#define TRACES (16)

pid_t pid = 0;

int target_raw[2];
int attack_raw[2];

FILE* target_out = NULL;
FILE* target_in = NULL;

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

void interact(mpz_t* tweak, mpz_t* plaintext, params* params) {
    params->interactions += 1;

    fprintf(target_in, "0\n");
    gmp_fprintf(target_in, "10:%032ZX\n", *tweak);
    fflush(target_in);

    int trace_length;
    fscanf(target_out, "%d,", &trace_length);
    printf("%d\n", trace_length);

    int trace[trace_length];
    for (int i = 0; i < trace_length - 1; i++) {
        fscanf(target_out, "%d,", &trace[i]);
    }
    fscanf(target_out, "%d\n", &trace[trace_length - 1]);

    int plaintext_length;
    fscanf(target_out, "%x:", &plaintext_length);
    gmp_fscanf(target_out, "%Zx", plaintext); // FIX THIS 
}

void get_traces(mpz_t tweaks[TRACES], unsigned char traces_start[TRACES][5000], unsigned char traces_end[TRACES][5000], mpz_t plaintexts[TRACES], params* params) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    for (int i = 0; i < 2; i++) {
        mpz_init(tweaks[i]);
        mpz_init(plaintexts[i]);

        mpz_urandomb(tweaks[i], state, 128);
        interact(&tweaks[i], &plaintexts[i], params);
    }

}

// The main attack
void attack(const char *config_file) {
    mpz_t tweaks[TRACES];
    unsigned char traces_start[TRACES][5000];
    unsigned char traces_end[TRACES][5000];
    mpz_t plaintexts[TRACES];

    params params;
    params.interactions = 0;

    get_traces(tweaks, traces_start, traces_end, plaintexts, &params);
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