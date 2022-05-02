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

int orders[NUM_POINTS] = {1647847, 1788443, 1012397, 1798649, 1218601, 1162877, 1686677, 1993127, 1072387, 1655593, 1099519, 1013153, 1682143};
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
    mpz_set_str(points[0].x,  "96189094486800337278539376050962196539704091031733447440458630334972020956155", 10); mpz_set_str(points[0].y,  "69193582105420457340242264805457933554592212349743638002220974828268650241613", 10);
    mpz_set_str(points[1].x,  "27854553996734993141866849434516774524031018219088032964764718224085069417109", 10); mpz_set_str(points[1].y,  "14722813938011051013524030478020004906103307456045340269053381521641801940013", 10);
    mpz_set_str(points[2].x,  "18212193350296493123388114929601819646202063780155138440964181055688266839144", 10); mpz_set_str(points[2].y,  "107329555721012227144728709675324427266365632811223525934961136950523469555610", 10);
    mpz_set_str(points[3].x,  "82075709761789178501105168135216482508226341527057391212967395017336591729286", 10); mpz_set_str(points[3].y,  "48601706735490839271378512665361964976378158012775586442045399108719306885593", 10);
    mpz_set_str(points[4].x,  "25435586486508779783867762210420066762659296632380293621384614832664017417599", 10); mpz_set_str(points[4].y,  "7887644176061798430116604617983281944457429815208147571831155686852324957342", 10);
    mpz_set_str(points[5].x,  "23282301770728480891093095412709230111397849161908642977755645685948386291356", 10); mpz_set_str(points[5].y,  "67866395459110004639908790126878048728627565629407450108322089662110907694615", 10);
    mpz_set_str(points[6].x,  "84339863565585692330483882318107223171602907800992730007412995478055169212609", 10); mpz_set_str(points[6].y,  "84595751638034978229893145669900532868849358056988058979980028958639470982481", 10);
    mpz_set_str(points[7].x,  "83532443275072910733923290966491964361396621338509305536179525946418351742182", 10); mpz_set_str(points[7].y,  "10328021816759495898999311378548844754356331074835737541154673612714044441781", 10);
    mpz_set_str(points[8].x,  "62626556521362916289061990564579493773970913058144933995478828404329758428878", 10); mpz_set_str(points[8].y,  "110923960277656116710966786341692630487223896971627122551315367310058557841840", 10);
    mpz_set_str(points[9].x,  "68552193811221982068598915095379407715990725267686578835522664613515891046472", 10); mpz_set_str(points[9].y,  "7178238675619017639884743956988973216208123107753430483432634731498800308024", 10);
    mpz_set_str(points[10].x, "87167640626688025779390161331724910814359364003834705926675941246561719614469", 10); mpz_set_str(points[10].y, "21178739363335112882279950148321540412895988185179990133336172608600752424414", 10);
    mpz_set_str(points[11].x, "97246058105194999953457754430200789209265924023151643719490447052273006891965", 10); mpz_set_str(points[11].y, "39566972891855909399955523965613469900521796164406512242283463351214873818515", 10);
    mpz_set_str(points[12].x, "98850148412583080123708140356580472064012840997323290471305047202745740911807", 10); mpz_set_str(points[12].y, "99674653486169577370354915841683739605468979315542205740735739710660262416563", 10);
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
    struct timeval timstr;
    gettimeofday(&timstr, NULL);
    double tic = timstr.tv_sec + (timstr.tv_usec / 1000000.0);

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

    gettimeofday(&timstr, NULL);
    double toc = timstr.tv_sec + (timstr.tv_usec / 1000000.0);

    printf("Attack time: %.2f seconds\n", toc - tic);
    gmp_printf("Target material (base 16): %ZX\n", key);
    printf("Interactions (base 10): %d\n", interactions);

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