#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LEN 128
#define PORT_NONE    (-1)
#define AUX_FLAG     0x80000000u

typedef struct BasicNode {
    struct BasicNode *child[2];
    int port;
} BasicNode;

typedef struct RouteItem {
    uint32_t ip;
    int mask_len;
    int port;
} RouteItem;

static BasicNode *basic_root = NULL;

#define ADV_L1_BITS 18
#define ADV_L2_BITS  6
#define ADV_L3_BITS  8
#define ADV_L1_SIZE (1u << ADV_L1_BITS)
#define ADV_L2_SIZE (1u << ADV_L2_BITS)
#define ADV_L3_SIZE (1u << ADV_L3_BITS)

static uint32_t *adv_l1_tbl = NULL;
static unsigned char *adv_l1_len = NULL;

static uint32_t *adv_l2_tbl = NULL;
static unsigned char *adv_l2_len = NULL;
static uint32_t adv_l2_blocks = 0, adv_l2_capacity = 0;

static uint32_t *adv_l3_tbl = NULL;
static unsigned char *adv_l3_len = NULL;
static uint32_t adv_l3_blocks = 0, adv_l3_capacity = 0;

static BasicNode *create_basic_node(void){
    BasicNode *node = (BasicNode *)malloc(sizeof(BasicNode));
    if(node == NULL){
        perror("malloc basic node failed");
        exit(1);
    }
    node->child[0] = node->child[1] = NULL;
    node->port = PORT_NONE;
    return node;
}

static uint32_t ip_to_uint(const char *ip_str){
    unsigned int a, b, c, d;
    if(sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4){
        fprintf(stderr, "invalid ip: %s\n", ip_str);
        exit(1);
    }
    return ((a & 255u) << 24) | ((b & 255u) << 16) | ((c & 255u) << 8) | (d & 255u);
}

static inline uint32_t port_to_cell(int port){
    return (uint32_t)(port + 1);
}

static inline int cell_to_port(uint32_t cell){
    return cell ? (int)cell - 1 : PORT_NONE;
}

static RouteItem *read_forwarding_table(const char *forward_file, size_t *route_cnt){
    FILE *fp = fopen(forward_file, "r");
    if(fp == NULL){
        perror("Open forwarding table fails");
        exit(1);
    }

    size_t cap = 1 << 20, cnt = 0;
    RouteItem *routes = (RouteItem *)malloc(sizeof(RouteItem) * cap);
    if(routes == NULL){
        perror("malloc routes failed");
        fclose(fp);
        exit(1);
    }

    char line[MAX_LINE_LEN], ip_str[32];
    int mask_len, port;

    while(fgets(line, sizeof(line), fp) != NULL){
        if(sscanf(line, "%31s %d %d", ip_str, &mask_len, &port) != 3) continue;
        if(mask_len < 0 || mask_len > 32) continue;

        if(cnt == cap){
            cap <<= 1;
            RouteItem *tmp = (RouteItem *)realloc(routes, sizeof(RouteItem) * cap);
            if(tmp == NULL){
                perror("realloc routes failed");
                free(routes);
                fclose(fp);
                exit(1);
            }
            routes = tmp;
        }

        routes[cnt].ip = ip_to_uint(ip_str);
        routes[cnt].mask_len = mask_len;
        routes[cnt].port = port;
        ++cnt;
    }

    fclose(fp);
    *route_cnt = cnt;
    return routes;
}

static void basic_insert(uint32_t ip, int mask_len, int port){
    BasicNode *cur = basic_root;

    if(mask_len == 0){
        cur->port = port;
        return;
    }

    for(int i = 31; i >= 32 - mask_len; --i){
        int bit = (ip >> i) & 1u;
        if(cur->child[bit] == NULL){
            cur->child[bit] = create_basic_node();
        }
        cur = cur->child[bit];
    }
    cur->port = port;
}

static int basic_lookup_single(uint32_t ip){
    BasicNode *cur = basic_root;
    int last_port = PORT_NONE;

    for(int i = 31; i >= 0 && cur != NULL; --i){
        if(cur->port != PORT_NONE) last_port = cur->port;
        cur = cur->child[(ip >> i) & 1u];
    }
    if(cur != NULL && cur->port != PORT_NONE) last_port = cur->port;

    return last_port;
}

static uint32_t new_block(uint32_t **tbl, unsigned char **len,
                          uint32_t *blocks, uint32_t *capacity,
                          uint32_t block_size, uint32_t init_cell, unsigned char init_len,
                          uint32_t init_cap){
    if(*blocks == *capacity){
        uint32_t new_cap = (*capacity == 0) ? init_cap : (*capacity << 1);

        uint32_t *new_tbl = (uint32_t *)realloc(*tbl, sizeof(uint32_t) * new_cap * block_size);
        if(new_tbl == NULL){
            perror("realloc table failed");
            exit(1);
        }
        *tbl = new_tbl;

        unsigned char *new_len = (unsigned char *)realloc(*len, sizeof(unsigned char) * new_cap * block_size);
        if(new_len == NULL){
            perror("realloc len failed");
            exit(1);
        }
        *len = new_len;

        *capacity = new_cap;
    }

    uint32_t block = (*blocks)++;
    uint32_t base = block * block_size;
    for(uint32_t i = 0; i < block_size; ++i){
        (*tbl)[base + i] = init_cell;
        (*len)[base + i] = init_len;
    }
    return block;
}

static uint32_t adv_ensure_l2_block(uint32_t idx1){
    uint32_t cell = adv_l1_tbl[idx1];
    if(cell & AUX_FLAG) return cell & ~AUX_FLAG;

    uint32_t block = new_block(&adv_l2_tbl, &adv_l2_len,
                               &adv_l2_blocks, &adv_l2_capacity,
                               ADV_L2_SIZE, cell, adv_l1_len[idx1], 2048);
    adv_l1_tbl[idx1] = AUX_FLAG | block;
    return block;
}

static uint32_t adv_ensure_l3_block(uint32_t pos2){
    uint32_t cell = adv_l2_tbl[pos2];
    if(cell & AUX_FLAG) return cell & ~AUX_FLAG;

    uint32_t block = new_block(&adv_l3_tbl, &adv_l3_len,
                               &adv_l3_blocks, &adv_l3_capacity,
                               ADV_L3_SIZE, cell, adv_l2_len[pos2], 1024);
    adv_l2_tbl[pos2] = AUX_FLAG | block;
    return block;
}

static void adv_insert_l1(uint32_t ip, int mask_len, int port){
    uint32_t key = ip >> (32 - ADV_L1_BITS);
    uint32_t start, span;

    if(mask_len == 0){
        start = 0;
        span = ADV_L1_SIZE;
    }else{
        int free_bits = ADV_L1_BITS - mask_len;
        start = (key >> free_bits) << free_bits;
        span = 1u << free_bits;
    }

    for(uint32_t i = start; i < start + span; ++i){
        if(adv_l1_len[i] <= (unsigned char)mask_len){
            adv_l1_len[i] = (unsigned char)mask_len;
            adv_l1_tbl[i] = port_to_cell(port);
        }
    }
}

static void adv_insert_l2(uint32_t ip, int mask_len, int port){
    uint32_t idx1 = ip >> 14;
    uint32_t base2 = adv_ensure_l2_block(idx1) * ADV_L2_SIZE;
    int remain = mask_len - ADV_L1_BITS;               // 1..6
    uint32_t key6 = (ip >> 8) & (ADV_L2_SIZE - 1u);
    uint32_t start = (key6 >> (ADV_L2_BITS - remain)) << (ADV_L2_BITS - remain);
    uint32_t span = 1u << (ADV_L2_BITS - remain);

    for(uint32_t i = start; i < start + span; ++i){
        uint32_t pos = base2 + i;
        if(adv_l2_len[pos] <= (unsigned char)mask_len){
            adv_l2_len[pos] = (unsigned char)mask_len;
            adv_l2_tbl[pos] = port_to_cell(port);
        }
    }
}

static void adv_insert_l3(uint32_t ip, int mask_len, int port){
    uint32_t idx1 = ip >> 14;
    uint32_t base2 = adv_ensure_l2_block(idx1) * ADV_L2_SIZE;
    uint32_t pos2 = base2 + ((ip >> 8) & (ADV_L2_SIZE - 1u));
    uint32_t base3 = adv_ensure_l3_block(pos2) * ADV_L3_SIZE;
    int remain = mask_len - (ADV_L1_BITS + ADV_L2_BITS);   // 1..8
    uint32_t low8 = ip & (ADV_L3_SIZE - 1u);
    uint32_t start = (low8 >> (ADV_L3_BITS - remain)) << (ADV_L3_BITS - remain);
    uint32_t span = 1u << (ADV_L3_BITS - remain);

    for(uint32_t i = start; i < start + span; ++i){
        uint32_t pos = base3 + i;
        if(adv_l3_len[pos] <= (unsigned char)mask_len){
            adv_l3_len[pos] = (unsigned char)mask_len;
            adv_l3_tbl[pos] = port_to_cell(port);
        }
    }
}

// return an array of ip represented by an unsigned integer, size is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file){
    FILE *fp = fopen(lookup_file, "r");
    if(fp == NULL){
        perror("Open lookup file fails");
        exit(1);
    }

    uint32_t *ip_vec = (uint32_t *)malloc(sizeof(uint32_t) * TEST_SIZE);
    if(ip_vec == NULL){
        perror("malloc ip_vec failed");
        fclose(fp);
        exit(1);
    }

    char line[MAX_LINE_LEN], ip_str[32];
    int count = 0;
    while(count < TEST_SIZE && fgets(line, sizeof(line), fp) != NULL){
        if(sscanf(line, "%31s", ip_str) != 1) continue;
        ip_vec[count++] = ip_to_uint(ip_str);
    }

    fclose(fp);
    return ip_vec;
}

// Constructing an advanced trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file){
    FILE *fp = fopen(forward_file, "r");
    if(fp == NULL){
        perror("Open forwarding table fails");
        exit(1);
    }

    basic_root = create_basic_node();

    char line[MAX_LINE_LEN], ip_str[32];
    int mask_len, port;
    while(fgets(line, sizeof(line), fp) != NULL){
        if(sscanf(line, "%31s %d %d", ip_str, &mask_len, &port) != 3) continue;
        if(mask_len < 0 || mask_len > 32) continue;
        basic_insert(ip_to_uint(ip_str), mask_len, port);
    }

    fclose(fp);
}

// Look up the ports of ip in file `lookup_file` using the basic tree
uint32_t *lookup_tree(uint32_t* ip_vec){
    uint32_t *res = (uint32_t *)malloc(sizeof(uint32_t) * TEST_SIZE);
    if(res == NULL){
        perror("malloc basic result failed");
        exit(1);
    }

    for(int i = 0; i < TEST_SIZE; ++i){
        res[i] = (uint32_t)basic_lookup_single(ip_vec[i]);
    }
    return res;
}

// Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
void create_tree_advance(const char* forward_file){
    size_t route_cnt = 0;
    RouteItem *routes = read_forwarding_table(forward_file, &route_cnt);

    adv_l1_tbl = (uint32_t *)calloc(ADV_L1_SIZE, sizeof(uint32_t));
    adv_l1_len = (unsigned char *)calloc(ADV_L1_SIZE, sizeof(unsigned char));
    if(adv_l1_tbl == NULL || adv_l1_len == NULL){
        perror("malloc l1 table failed");
        free(routes);
        exit(1);
    }

    for(size_t i = 0; i < route_cnt; ++i){
        if(routes[i].mask_len <= ADV_L1_BITS)
            adv_insert_l1(routes[i].ip, routes[i].mask_len, routes[i].port);
    }
    for(size_t i = 0; i < route_cnt; ++i){
        if(routes[i].mask_len > ADV_L1_BITS && routes[i].mask_len <= ADV_L1_BITS + ADV_L2_BITS)
            adv_insert_l2(routes[i].ip, routes[i].mask_len, routes[i].port);
    }
    for(size_t i = 0; i < route_cnt; ++i){
        if(routes[i].mask_len > ADV_L1_BITS + ADV_L2_BITS)
            adv_insert_l3(routes[i].ip, routes[i].mask_len, routes[i].port);
    }

    free(routes);
}

static inline int adv_lookup_single(uint32_t ip){
    uint32_t cell1 = adv_l1_tbl[ip >> 14];
    if((cell1 & AUX_FLAG) == 0) return cell_to_port(cell1);

    uint32_t pos2 = (cell1 & ~AUX_FLAG) * ADV_L2_SIZE + ((ip >> 8) & (ADV_L2_SIZE - 1u));
    uint32_t cell2 = adv_l2_tbl[pos2];
    if((cell2 & AUX_FLAG) == 0) return cell_to_port(cell2);

    return cell_to_port(adv_l3_tbl[(cell2 & ~AUX_FLAG) * ADV_L3_SIZE + (ip & (ADV_L3_SIZE - 1u))]);
}

// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance(uint32_t* ip_vec){
    uint32_t *res = (uint32_t *)malloc(sizeof(uint32_t) * TEST_SIZE);
    if(res == NULL){
        perror("malloc advanced result failed");
        exit(1);
    }

    for(int i = 0; i < TEST_SIZE; ++i){
        res[i] = (uint32_t)adv_lookup_single(ip_vec[i]);
    }
    return res;
}