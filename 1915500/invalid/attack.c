#include "attack.h"

#define BUFFER_SIZE (80)
#define NUM_POINTS (13)

typedef struct {
    mpz_t x;
    mpz_t y;
} point;

pid_t pid = 0;

int target_raw[2];
int attack_raw[2];

FILE* target_out = NULL;
FILE* target_in = NULL;

int orders[NUM_POINTS] = {3819671, 2281327, 1647847, 1788443, 2914393, 1012397, 8911031, 2975243, 3395983, 3927941, 1798649, 1218601, 2739613};
point points[NUM_POINTS];

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

void assign_points() {
    for (int i = 0; i < NUM_POINTS; i++) {
        mpz_inits(points[i].x, points[i].y, NULL);
    }
    mpz_set_str(points[0].x,  "107533217531176646258510464537237584264518580873418386444162120260198111762699", 10); mpz_set_str(points[0].y,  "53599883523427818341719914420161479231227520116435819131016303933210229789697", 10);
    mpz_set_str(points[1].x,  "67724721870889584215751452442188512186370461596540611987504566188157166012529", 10); mpz_set_str(points[1].y,  "29380972087542509903107248623826889127080800405771566347024975864007340128568", 10);
    mpz_set_str(points[2].x,  "96189094486800337278539376050962196539704091031733447440458630334972020956155", 10); mpz_set_str(points[2].y,  "69193582105420457340242264805457933554592212349743638002220974828268650241613", 10);
    mpz_set_str(points[3].x,  "27854553996734993141866849434516774524031018219088032964764718224085069417109", 10); mpz_set_str(points[3].y,  "14722813938011051013524030478020004906103307456045340269053381521641801940013", 10);
    mpz_set_str(points[4].x,  "20979015460493628799211877556183158051322757414964977139207539095465254373192", 10); mpz_set_str(points[4].y,  "107454843553513466798984248164659920375037972000903721449049976060986024888927", 10);
    mpz_set_str(points[5].x,  "18212193350296493123388114929601819646202063780155138440964181055688266839144", 10); mpz_set_str(points[5].y,  "107329555721012227144728709675324427266365632811223525934961136950523469555610", 10);
    mpz_set_str(points[6].x,  "105606134984199884449948132947712379486279035590721835907624086038181840524869", 10); mpz_set_str(points[6].y,  "62360618061432858780233983845747222437255187324463623800159592557346472785008", 10);
    mpz_set_str(points[7].x,  "93167339315366751342397632863829203993192820006750023185856471295756861743931", 10); mpz_set_str(points[7].y,  "105361318080699480018445126120754658063889153995803713707886585489888409374163", 10);
    mpz_set_str(points[8].x,  "4889157100432514232951120387526708114287803490943324008962474787709135691082", 10); mpz_set_str(points[8].y,  "45721130768468337447958398635585211412672091649215965961348503115316921561246", 10);
    mpz_set_str(points[9].x,  "101032217841760319724520914489718972210145073237698506048037696065194012759210", 10); mpz_set_str(points[9].y,  "87347239302301147696456646384200333489869720367215299631961213438612802504049", 10);
    mpz_set_str(points[10].x, "82075709761789178501105168135216482508226341527057391212967395017336591729286", 10); mpz_set_str(points[10].y, "48601706735490839271378512665361964976378158012775586442045399108719306885593", 10);
    mpz_set_str(points[11].x, "25435586486508779783867762210420066762659296632380293621384614832664017417599", 10); mpz_set_str(points[11].y, "7887644176061798430116604617983281944457429815208147571831155686852324957342", 10);
    mpz_set_str(points[12].x, "92034705847690435119106913356972641486567169727242951331903128054943299224825", 10); mpz_set_str(points[12].y, "23878155531547513695804885800531613540663080302535273153382460312181732396522", 10);
}

void interact(point *p, point *q, unsigned char *interactions) {
    (*interactions)++;

    gmp_fprintf(target_in, "%ZX\n", p->x);
    gmp_fprintf(target_in, "%ZX\n", p->y);
    fflush(target_in);

    gmp_fscanf(target_out, "%ZX\n", &(q->x));
    gmp_fscanf(target_out, "%ZX", &(q->y));
}

void get_multiplied_points(point multiplied_points[NUM_POINTS], unsigned char* interactions) {
    for (int i = 0; i < NUM_POINTS; i++) {
        mpz_inits(multiplied_points[i].x, multiplied_points[i].y, NULL);
        interact(&points[i], &multiplied_points[i], interactions);
    }
}

void add_point(point *p, point *q, mpz_t *a_4, mpz_t* base) {
    mpz_t dydx, temp;
    mpz_inits(dydx, temp, NULL);

    if (mpz_cmp(p->x, q->x) == 0 && mpz_cmp(p->y, q->y) == 0) {
        mpz_mul(dydx, p->x, p->x);
        mpz_mul_ui(dydx, dydx, 3);
        mpz_add(dydx, dydx, *a_4);
        mpz_mul_ui(temp, p->y, 2);
        mpz_invert(temp, temp, *base);
        mpz_mul(dydx, dydx, temp);
    }
    else {
        mpz_sub(dydx, q->y, p->y);
        mpz_sub(temp, q->x, p->x);
        mpz_invert(temp, temp, *base);
        mpz_mul(dydx, dydx, temp);
    }

    mpz_mul(temp, dydx, dydx);
    mpz_sub(temp, temp, p->x);
    mpz_sub(temp, temp, q->x);
    mpz_mod(q->x, temp, *base);

    mpz_sub(temp, p->x, q->x);
    mpz_mul(temp, dydx, temp);
    mpz_sub(temp, temp, p->y);
    mpz_mod(q->y, temp, *base);

    mpz_clears(dydx, temp, NULL);
}

int calc_remainder(point *original_point, point *multiplied_point, mpz_t *a_4, mpz_t *base) {
    int i = 1;

    point temp;
    mpz_inits(temp.x, temp.y, NULL);
    mpz_set(temp.x, original_point->x);
    mpz_set(temp.y, original_point->y);

    while (mpz_cmp(temp.x, multiplied_point->x) || mpz_cmp(temp.y, multiplied_point->y)) {
        add_point(original_point, &temp, a_4, base);
        i++;
    }
    
    mpz_clears(temp.x, temp.y, NULL);

    return i;
}

void calc_remainders(int remainders[NUM_POINTS], point points[NUM_POINTS], point multiplied_points[NUM_POINTS]) {
    mpz_t a_4, base;
    mpz_inits(a_4, base, NULL);
    mpz_set_str(a_4, "115792089210356248762697446949407573530086143415290314195533631308867097853948", 10);
    mpz_set_str(base, "115792089210356248762697446949407573530086143415290314195533631308867097853951", 10);

    #pragma omp parallel for num_threads(16)
    for (int i = 0; i < NUM_POINTS; i++) {
        remainders[i] = calc_remainder(&points[i], &multiplied_points[i], &a_4, &base);
        // printf("%d\n", remainders[i]);
    }

    for (int i = 0; i < NUM_POINTS; i++) {
        mpz_clears(multiplied_points[i].x, multiplied_points[i].y, NULL);
    }

    mpz_clears(a_4, base, NULL);
}

void chinese_remainder(int remainders[NUM_POINTS], mpz_t *key) {
    mpz_t product, pp, temp;
    mpz_inits(product, pp, temp, NULL);

    mpz_set_ui(product, 1);
    
    for (int i = 0; i < NUM_POINTS; i++) {
        mpz_mul_ui(product, product, orders[i]);
    }

    mpz_set_ui(*key, 0);

    for (int i = 0; i < NUM_POINTS; i++) {
        mpz_fdiv_q_ui(pp, product, orders[i]);
        mpz_set_ui(temp, orders[i]);
        mpz_invert(temp, pp, temp);
        mpz_mul(temp, temp, pp);
        mpz_mul_ui(temp, temp, remainders[i]);
        mpz_add(*key, *key, temp);
    }

    mpz_mod(*key, *key, product);

    mpz_clears(product, pp, temp, NULL);
}

void clear_points() {
    for (int i = 0; i < NUM_POINTS; i++) {
        mpz_clears(points[i].x, points[i].y, NULL);
    }
}

void attack() {
    point multiplied_points[NUM_POINTS];
    int remainders[NUM_POINTS];
    unsigned char interactions = 0;
    mpz_t key;
    mpz_init(key);

    assign_points();
    get_multiplied_points(multiplied_points, &interactions);
    calc_remainders(remainders, points, multiplied_points);
    chinese_remainder(remainders, &key);
    clear_points();

    printf("Interactions: %d\n", interactions);
    gmp_printf("Key: %ZX\n", key);

    mpz_clear(key);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, &cleanup);

    if (pipe(target_raw) == -1) abort();
    if (pipe(attack_raw) == -1) abort();

    pid = fork();
    if (pid > 0) {
        if ((target_out = fdopen(attack_raw[0], "r")) == NULL) abort();
        if ((target_in = fdopen(target_raw[1], "w")) == NULL) abort();
        attack();
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