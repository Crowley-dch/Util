#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ROTR(x,n) ((x >> n) | (x << (32 - n)))
#define SHR(x,n)  (x >> n)
#define CH(x,y,z)  ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x)     (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)     (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x)    (ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3))
#define SIG1(x)    (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

const uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256(const uint8_t *msg, size_t len, uint8_t hash[32]) {
    uint32_t h[8] = {
      0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    uint64_t bitlen = len * 8;
    size_t new_len = len + 1;
    while ((new_len % 64) != 56) new_len++;

    uint8_t *data = calloc(1, new_len + 8);
    memcpy(data, msg, len);
    data[len] = 0x80;
    for (int i = 0; i < 8; i++)
        data[new_len + i] = (bitlen >> (56 - 8*i)) & 0xFF;

    for (size_t offset = 0; offset < new_len + 8; offset += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = (data[offset + i*4] << 24) |
                   (data[offset + i*4 + 1] << 16) |
                   (data[offset + i*4 + 2] << 8) |
                   (data[offset + i*4 + 3]);
        }
        for (int i = 16; i < 64; i++)
            w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h0 = h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h0 + EP1(e) + CH(e,f,g) + k[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a,b,c);
            h0 = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h0;
    }

    for (int i = 0; i < 8; i++) {
        hash[i*4] = (h[i] >> 24) & 0xFF;
        hash[i*4 + 1] = (h[i] >> 16) & 0xFF;
        hash[i*4 + 2] = (h[i] >> 8) & 0xFF;
        hash[i*4 + 3] = h[i] & 0xFF;
    }

    free(data);
}

void hmac_sha256(const uint8_t *key, size_t key_len, 
                 const uint8_t *msg, size_t msg_len, 
                 uint8_t *out) {
    uint8_t k_ipad[64] = {0};
    uint8_t k_opad[64] = {0};
    uint8_t tmp_key[32];

    if (key_len > 64) {
        sha256(key, key_len, tmp_key);
        key = tmp_key;
        key_len = 32;
    }

    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    uint8_t inner_hash[32];
    uint8_t inner_msg[64 + msg_len];
    
    memcpy(inner_msg, k_ipad, 64);
    memcpy(inner_msg + 64, msg, msg_len);
    sha256(inner_msg, 64 + msg_len, inner_hash);

    uint8_t outer_msg[64 + 32];
    memcpy(outer_msg, k_opad, 64);
    memcpy(outer_msg + 64, inner_hash, 32);
    sha256(outer_msg, 64 + 32, out);

    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memset(tmp_key, 0, 32);
}

void secure_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        perror("Failed to open /dev/urandom");
        exit(1);
    }
    if (fread(buf, 1, len, f) != len) {
        perror("Failed to read from /dev/urandom");
        exit(1);
    }
    fclose(f);
}

void generate_secure_bits(const char *passphrase, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        exit(1);
    }

    uint8_t salt[32];
    secure_random(salt, 16);  

    uint64_t extra_entropy[2] = {time(NULL), getpid()};
    
    uint8_t tmp_hash[32];
    sha256((uint8_t*)extra_entropy, sizeof(extra_entropy), tmp_hash);
    
    memcpy(salt + 16, tmp_hash + 16, 16);

    uint8_t hash[32];
    uint8_t input[512];
    size_t passlen = strlen(passphrase);
    const size_t total_bytes = 125000; 
    size_t bytes_written = 0;

    hmac_sha256(salt, 32, (uint8_t*)passphrase, passlen, hash);

    while (bytes_written < total_bytes) {
        size_t offset = 0;
        memcpy(input + offset, hash, 32); offset += 32;
        input[offset++] = (bytes_written >> 24) & 0xFF;
        input[offset++] = (bytes_written >> 16) & 0xFF;
        input[offset++] = (bytes_written >> 8) & 0xFF;
        input[offset++] = bytes_written & 0xFF;
        memcpy(input + offset, salt, 32); offset += 32;

        hmac_sha256(salt, 32, input, offset, hash);
        bytes_written += 32;

        if (bytes_written <= total_bytes) {
            fwrite(hash, 1, 32, fp);
        } else {
            fwrite(hash, 1, total_bytes - (bytes_written - 32), fp);
            bytes_written = total_bytes;
        }
    }

    fclose(fp);
    printf("✔ Генератор с HMAC-SHA256: %zu байт записано в '%s'\n", total_bytes, filename);
    printf("Соль (hex): ");
    for (int i = 0; i < 32; i++) printf("%02x", salt[i]);
    printf("\n");

    memset(salt, 0, 32);
    memset(hash, 0, 32);
    memset(input, 0, 512);
}

int main() {
    char passphrase[256];
    printf("Введите парольную фразу: ");
    fgets(passphrase, sizeof(passphrase), stdin);
    passphrase[strcspn(passphrase, "\n")] = '\0';

    generate_secure_bits(passphrase, "key.bin");
    return 0;
}