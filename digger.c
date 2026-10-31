// digger.c — Agentic Pixels free-dig nonce searcher.
//
// Puzzle (from the verified AgenticPixels contract, BSC 0xcb2Be11420eFbb51b19ADC76732550d5D40A3E5f):
//   startDig() gives your wallet a ticket {seed, icon, difficulty} (valid 24h).
//   claimFree(nonce) accepts when  matched(keccak256(seed || nonce_be256), icon) >= difficulty,
//   where matched() counts how many leading bits of the hash's first 64 bits equal the icon's
//   64-bit pattern. Expected work: 2^difficulty hashes. This tool finds such a nonce.
//
// The seed is public on-chain data (emitted in the DigStarted event). This tool holds NO keys
// and signs nothing; the found nonce is claimed from the agent wallet by the operator.
//
// Build:  gcc -O3 -march=native -pthread -o digger digger.c     (or: make)
// Usage:
//   ./digger --selftest
//   ./digger --eval   <seed_hex64> <icon 0-15> <nonce_dec>
//   ./digger --search <seed_hex64> <icon 0-15> <difficulty> <start_dec> <end_dec> <threads>
// Search prints progress to stderr; on success prints a FOUND line to stdout and writes found.txt.
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#define ROTL(x,y) (((x)<<(y))|((x)>>(64-(y))))
static const uint64_t RC[24]={
0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const int rotc[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int piln[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
static void keccakf(uint64_t st[25]){
    uint64_t bc[5], t;
    for(int rnd=0;rnd<24;rnd++){
        for(int i=0;i<5;i++) bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
        for(int i=0;i<5;i++){ t=bc[(i+4)%5]^ROTL(bc[(i+1)%5],1); for(int j=0;j<25;j+=5) st[j+i]^=t; }
        t=st[1];
        for(int i=0;i<24;i++){ int j=piln[i]; uint64_t tmp=st[j]; st[j]=ROTL(t,rotc[i]); t=tmp; }
        for(int j=0;j<25;j+=5){ for(int i=0;i<5;i++) bc[i]=st[j+i]; for(int i=0;i<5;i++) st[j+i]^=(~bc[(i+1)%5])&bc[(i+2)%5]; }
        st[0]^=RC[rnd];
    }
}
// The 16 dig icons (PixelTables.ICONS), each an 8x8 grid, leftmost pixel = most significant bit.
static const uint64_t ICONS[16]={
0x66ffffff7e3c1800ULL,0x1818ff7e3c664200ULL,0x70888f8a72000000ULL,0x3c4299a5a599423cULL,
0x7eff9999ff665a00ULL,0x3c7edbffffffa500ULL,0x0103068c58306880ULL,0x3c18183c7effff7eULL,
0x7edbff7e3c180000ULL,0x9999ffffff7e0000ULL,0x0e1c387e1c386080ULL,0x3860c0c0c0603800ULL,
0x3c6effbd183c3c00ULL,0x246618662418183cULL,0x24187edbffbda518ULL,0x7884060a12204080ULL};

static uint64_t BASE[25];
static void build_base(const uint8_t seed[32]){
    uint8_t blk[136]; memset(blk,0,sizeof blk); memcpy(blk,seed,32);
    blk[64]=0x01; blk[135]|=0x80;                 // message is 64 bytes: seed || nonce(32B BE)
    memset(BASE,0,sizeof BASE);
    for(int i=0;i<136;i++) ((uint8_t*)BASE)[i]^=blk[i];
}
// nonce < 2^64: bytes 32..55 of the message stay zero; the low 8 bytes land in lane 7.
static inline void hash_nonce(uint64_t nonce, uint8_t out[32]){
    uint64_t a[25]; memcpy(a,BASE,sizeof a);
    a[7]=__builtin_bswap64(nonce);
    keccakf(a);
    memcpy(out,(uint8_t*)a,32);
}
static void keccak256(const uint8_t*in,size_t len,uint8_t out[32]){
    uint8_t blk[136]; memset(blk,0,sizeof blk); memcpy(blk,in,len);
    blk[len]=0x01; blk[135]|=0x80;
    uint64_t a[25]; memset(a,0,sizeof a);
    for(size_t i=0;i<136;i++) ((uint8_t*)a)[i]^=blk[i];
    keccakf(a); memcpy(out,(uint8_t*)a,32);
}
static inline int match_count(const uint8_t h[32], uint64_t icon){
    uint64_t top; memcpy(&top,h,8); top=__builtin_bswap64(top);   // first 64 bits of h, big-endian
    uint64_t x=top^icon;
    if(x==0) return 64;
    return __builtin_clzll(x);
}
static int hexval(char c){ return c<='9'?c-'0':c<='f'?c-'a'+10:c-'A'+10; }
static int parse_seed(const char*s,uint8_t out[32]){
    if(strlen(s)!=64) return 0;
    for(int i=0;i<32;i++){ if(!isxdigit((unsigned char)s[2*i])||!isxdigit((unsigned char)s[2*i+1])) return 0; out[i]=(hexval(s[2*i])<<4)|hexval(s[2*i+1]); }
    return 1;
}

static volatile int g_found=0;
static uint64_t g_diff, g_icon;
static uint64_t g_start, g_end;
static int g_nthreads=1;
static volatile uint64_t g_tried=0;
static void* worker(void*arg){
    uint64_t tid=(uint64_t)arg, nonce;
    uint8_t h[32];
    uint64_t local=0;
    for(nonce=g_start+tid; nonce<g_end && !g_found; nonce+=g_nthreads){
        hash_nonce(nonce,h);
        if(++local>=8192){ __sync_fetch_and_add(&g_tried,local); local=0; }
        if((uint64_t)match_count(h,g_icon)>=g_diff){
            if(!__sync_lock_test_and_set(&g_found,1)){
                printf("FOUND nonce=%llu hash=", (unsigned long long)nonce);
                for(int i=0;i<32;i++) printf("%02x",h[i]);
                printf(" matched=%d\n", match_count(h,g_icon));
                fflush(stdout);
                FILE*f=fopen("found.txt","w");
                if(f){ fprintf(f,"nonce=%llu\n",(unsigned long long)nonce); fclose(f); }
            }
            return NULL;
        }
    }
    return NULL;
}

int main(int argc,char**argv){
    if(argc>=2 && !strcmp(argv[1],"--selftest")){
        uint8_t out[32]; keccak256((const uint8_t*)"",0,out);
        printf("keccak256(\"\") = "); for(int i=0;i<32;i++) printf("%02x",out[i]); printf("\n");
        printf("expected       = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\n");
        return 0;
    }
    if(argc==5 && !strcmp(argv[1],"--eval")){
        uint8_t seed[32]; if(!parse_seed(argv[2],seed)){ fprintf(stderr,"bad seed\n"); return 2; }
        int icon=atoi(argv[3]); uint64_t nonce=strtoull(argv[4],NULL,10);
        build_base(seed);
        uint8_t h[32]; hash_nonce(nonce,h);
        printf("hash="); for(int i=0;i<32;i++) printf("%02x",h[i]);
        printf(" matched=%d\n", match_count(h,ICONS[icon]));
        return 0;
    }
    if(argc==8 && !strcmp(argv[1],"--search")){
        uint8_t seed[32]; if(!parse_seed(argv[2],seed)){ fprintf(stderr,"bad seed\n"); return 2; }
        int icon=atoi(argv[3]);
        g_icon=ICONS[icon]; g_diff=strtoull(argv[4],NULL,10);
        g_start=strtoull(argv[5],NULL,10); g_end=strtoull(argv[6],NULL,10);
        g_nthreads=atoi(argv[7]); if(g_nthreads<1) g_nthreads=1;
        build_base(seed);
        fprintf(stderr,"searching icon=%d difficulty=%llu range=[%llu,%llu) threads=%d\n",
            icon,(unsigned long long)g_diff,(unsigned long long)g_start,(unsigned long long)g_end,g_nthreads);
        pthread_t th[256]; struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
        for(long i=0;i<g_nthreads;i++) pthread_create(&th[i],NULL,worker,(void*)i);
        uint64_t last=0;
        while(!g_found){
            int alive=0; for(int i=0;i<g_nthreads;i++) // progress reporting omitted
            // simple liveness: check if all joined via tried counter growth is unreliable; use join with timeout pattern:
            break; // fall through to join loop below
        }
        for(int i=0;i<g_nthreads;i++)pthread_join(th[i],NULL);
        clock_gettime(CLOCK_MONOTONIC,&t1);
        double dt=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
        fprintf(stderr,"done: tried=%llu in %.1fs (%.2f MH/s) found=%d\n",
            (unsigned long long)g_tried, dt, dt>0?(double)g_tried/dt/1e6:0, g_found);
        return g_found?0:1;
    }
    fprintf(stderr,"usage: digger --selftest | --eval <seed> <icon> <nonce> | --search <seed> <icon> <difficulty> <start> <end> <threads>\n");
    return 2;
}
