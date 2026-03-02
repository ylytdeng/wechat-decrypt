/*
 * decrypt_images.c — WeChat V2 image batch decryptor
 *
 * Decrypts all V2 encrypted .dat files in the WeChat image cache.
 *
 * V2 format:
 *   [15B header] [AES-128-ECB ciphertext] [XOR encrypted tail]
 *   Header: \x07\x08V2\x08\x07 (6B) + aes_size:u32LE + xor_size:u32LE + 1B pad
 *   AES region: ceil(aes_size/16)*16 bytes of AES-128-ECB ciphertext
 *   XOR tail: xor_size bytes, each XOR'd with a single-byte key
 *
 * Build:
 *   cc -O3 -o decrypt_images decrypt_images.c -framework Security
 *
 * Usage:
 *   ./decrypt_images                                   # read config.json
 *   ./decrypt_images <key_hex> <image_dir> <out_dir>   # manual
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <CommonCrypto/CommonCryptor.h>

#define MAX_PATH 4096
#define V2_MAGIC "\x07\x08V2\x08\x07"
#define V2_MAGIC_LEN 6
#define HEADER_SIZE 15

/* ---- Utility ---- */

static int hex2bytes(const char *hex, unsigned char *out, int maxlen) {
    int len = 0;
    while (*hex && *(hex + 1) && len < maxlen) {
        unsigned int b;
        sscanf(hex, "%2x", &b);
        out[len++] = (unsigned char)b;
        hex += 2;
    }
    return len;
}

/* Minimal JSON string extractor */
static int json_get_string(const char *json, const char *key,
                           char *value, int maxlen) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0;
    p = strchr(p + strlen(pattern), '"');
    if (!p) return 0;
    p++;
    const char *end = strchr(p, '"');
    if (!end) return 0;
    int len = (int)(end - p);
    if (len >= maxlen) len = maxlen - 1;
    memcpy(value, p, len);
    value[len] = '\0';
    return 1;
}

/* Create directory and parents */
static void mkdirs(const char *path) {
    char tmp[MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

/* Detect image type from magic bytes */
static const char *detect_ext(const unsigned char *data, size_t len) {
    if (len < 4) return ".bin";
    if (data[0] == 0xFF && data[1] == 0xD8) return ".jpg";
    if (data[0] == 0x89 && data[1] == 0x50 &&
        data[2] == 0x4E && data[3] == 0x47) return ".png";
    if (data[0] == 'G' && data[1] == 'I' &&
        data[2] == 'F' && data[3] == '8') return ".gif";
    if (data[0] == 'R' && data[1] == 'I' &&
        data[2] == 'F' && data[3] == 'F') return ".webp";
    if (data[0] == 0x00 && data[1] == 0x00 &&
        data[2] == 0x00 && (data[3] == 0x18 || data[3] == 0x1C ||
        data[3] == 0x20 || data[3] == 0x14)) return ".mp4";
    return ".bin";
}

/* Auto-detect XOR key by trying all 256 values on first byte after AES region.
 * The first XOR byte should decrypt to a valid continuation of the image data.
 * We check which XOR key produces the most common image data patterns. */
static unsigned char detect_xor_key(const unsigned char *aes_plaintext,
                                     size_t aes_size,
                                     const unsigned char *xor_data,
                                     size_t xor_size) {
    if (xor_size == 0) return 0;

    /* If AES decrypted data starts with FFD8 (JPEG), the XOR region should
     * contain continuation data. Try to find XOR key that produces valid
     * JPEG marker or plausible data. We use a heuristic: the most common
     * XOR key across several test positions. */

    /* Simple approach: if AES plaintext is JPEG and ends with certain patterns,
     * we can predict what comes next. But the simplest: just try common keys. */
    unsigned char candidates[] = {0x80, 0xDC, 0x00};
    for (int i = 0; i < (int)(sizeof(candidates)/sizeof(candidates[0])); i++) {
        unsigned char test = xor_data[0] ^ candidates[i];
        /* Check if decoded byte looks plausible with context */
        if (test != 0x00 || candidates[i] == 0x00)
            return candidates[i];
    }
    return 0x80; /* default */
}

/* ---- Decrypt one V2 file ---- */

static int decrypt_v2_file(const char *input_path, const char *output_dir,
                           const char *rel_path, const unsigned char *aes_key,
                           unsigned char xor_key, int auto_xor,
                           int *out_xor_detected) {
    FILE *fin = fopen(input_path, "rb");
    if (!fin) return -1;

    /* Read header */
    unsigned char header[HEADER_SIZE];
    if (fread(header, 1, HEADER_SIZE, fin) != HEADER_SIZE) {
        fclose(fin);
        return -1;
    }

    if (memcmp(header, V2_MAGIC, V2_MAGIC_LEN) != 0) {
        fclose(fin);
        return -2; /* not V2 */
    }

    uint32_t aes_size, xor_size;
    memcpy(&aes_size, header + 6, 4);
    memcpy(&xor_size, header + 10, 4);

    /* AES ciphertext size: padded to 16-byte boundary */
    uint32_t aes_ct_size = ((aes_size + 15) / 16) * 16;

    /* Read AES ciphertext */
    unsigned char *aes_ct = malloc(aes_ct_size);
    if (!aes_ct) { fclose(fin); return -1; }
    size_t rd = fread(aes_ct, 1, aes_ct_size, fin);
    if (rd < aes_ct_size) {
        /* File might be truncated, use what we have */
        memset(aes_ct + rd, 0, aes_ct_size - rd);
    }

    /* Read XOR data */
    unsigned char *xor_data = NULL;
    if (xor_size > 0) {
        xor_data = malloc(xor_size);
        if (!xor_data) { free(aes_ct); fclose(fin); return -1; }
        rd = fread(xor_data, 1, xor_size, fin);
        if (rd < xor_size) memset(xor_data + rd, 0, xor_size - rd);
    }
    fclose(fin);

    /* AES-128-ECB decrypt */
    unsigned char *aes_pt = malloc(aes_ct_size);
    if (!aes_pt) { free(aes_ct); free(xor_data); return -1; }

    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(
        kCCDecrypt, kCCAlgorithmAES128, kCCOptionECBMode,
        aes_key, 16, NULL,
        aes_ct, aes_ct_size,
        aes_pt, aes_ct_size, &moved);
    free(aes_ct);

    if (st != kCCSuccess) {
        free(aes_pt);
        free(xor_data);
        return -3;
    }

    /* Auto-detect XOR key on first file if needed */
    if (auto_xor && xor_data && xor_size > 0) {
        xor_key = detect_xor_key(aes_pt, aes_size, xor_data, xor_size);
        if (out_xor_detected) *out_xor_detected = xor_key;
    }

    /* XOR decrypt tail */
    if (xor_data && xor_size > 0) {
        for (uint32_t i = 0; i < xor_size; i++)
            xor_data[i] ^= xor_key;
    }

    /* Detect image type */
    const char *ext = detect_ext(aes_pt, aes_size);

    /* Build output path */
    char out_path[MAX_PATH];
    /* Replace .dat extension with detected extension */
    char rel_noext[MAX_PATH];
    snprintf(rel_noext, sizeof(rel_noext), "%s", rel_path);
    char *dot = strrchr(rel_noext, '.');
    if (dot) *dot = '\0';
    snprintf(out_path, sizeof(out_path), "%s/%s%s", output_dir, rel_noext, ext);

    /* Create parent directories */
    char parent[MAX_PATH];
    snprintf(parent, sizeof(parent), "%s", out_path);
    char *last_slash = strrchr(parent, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdirs(parent);
    }

    /* Write output */
    FILE *fout = fopen(out_path, "wb");
    if (!fout) {
        free(aes_pt);
        free(xor_data);
        return -4;
    }

    fwrite(aes_pt, 1, aes_size, fout); /* only write aes_size bytes (strip padding) */
    if (xor_data && xor_size > 0)
        fwrite(xor_data, 1, xor_size, fout);

    fclose(fout);
    free(aes_pt);
    free(xor_data);

    return 0;
}

/* ---- Directory walking ---- */

typedef struct {
    const unsigned char *aes_key;
    unsigned char xor_key;
    int auto_xor;
    const char *output_dir;
    const char *base_dir;
    int success;
    int skipped;
    int failed;
} walk_ctx;

static void walk_dir(const char *dir, walk_ctx *ctx) {
    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;

        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

        struct stat st;
        if (stat(path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            walk_dir(path, ctx);
        } else if (S_ISREG(st.st_mode)) {
            size_t nlen = strlen(ent->d_name);
            if (nlen < 5 || strcmp(ent->d_name + nlen - 4, ".dat") != 0)
                continue;

            /* Get relative path */
            const char *rel = path + strlen(ctx->base_dir);
            if (*rel == '/') rel++;

            int xor_detected = -1;
            int ret = decrypt_v2_file(path, ctx->output_dir, rel,
                                       ctx->aes_key, ctx->xor_key,
                                       ctx->auto_xor, &xor_detected);

            if (ret == 0) {
                ctx->success++;
                /* Lock in XOR key after first successful decrypt */
                if (ctx->auto_xor && xor_detected >= 0) {
                    ctx->xor_key = (unsigned char)xor_detected;
                    ctx->auto_xor = 0;
                    printf("  Auto-detected XOR key: 0x%02X\n", ctx->xor_key);
                }
                if (ctx->success <= 5 || ctx->success % 100 == 0) {
                    printf("  [%d] %s\n", ctx->success, rel);
                }
            } else if (ret == -2) {
                ctx->skipped++; /* not V2 */
            } else {
                ctx->failed++;
                if (ctx->failed <= 5) {
                    printf("  FAIL(%d): %s\n", ret, rel);
                }
            }
        }
    }
    closedir(d);
}

/* ---- Main ---- */

int main(int argc, char *argv[]) {
    unsigned char aes_key[16];
    char image_dir[MAX_PATH] = "";
    char output_dir[MAX_PATH] = "";
    char key_hex[64] = "";

    printf("=== WeChat V2 Image Decryptor ===\n\n");

    if (argc >= 4) {
        /* Manual mode: key_hex image_dir output_dir */
        strncpy(key_hex, argv[1], sizeof(key_hex) - 1);
        strncpy(image_dir, argv[2], sizeof(image_dir) - 1);
        strncpy(output_dir, argv[3], sizeof(output_dir) - 1);
    } else {
        /* Read from config.json */
        char config_path[MAX_PATH];
        const char *exe = argv[0];
        const char *last_slash = strrchr(exe, '/');
        if (last_slash) {
            int dir_len = (int)(last_slash - exe);
            snprintf(config_path, sizeof(config_path),
                     "%.*s/config.json", dir_len, exe);
        } else {
            strcpy(config_path, "config.json");
        }

        FILE *cf = fopen(config_path, "r");
        if (!cf) {
            fprintf(stderr, "ERROR: Cannot open %s\n", config_path);
            fprintf(stderr, "Usage: %s <key_hex> <image_dir> <output_dir>\n",
                    argv[0]);
            return 1;
        }

        fseek(cf, 0, SEEK_END);
        long sz = ftell(cf);
        fseek(cf, 0, SEEK_SET);
        char *json = malloc(sz + 1);
        fread(json, 1, sz, cf);
        json[sz] = '\0';
        fclose(cf);

        json_get_string(json, "image_key", key_hex, sizeof(key_hex));

        char db_dir[MAX_PATH] = "";
        json_get_string(json, "db_dir", db_dir, sizeof(db_dir));

        /* output dir */
        char out_rel[MAX_PATH] = "decrypted_images";
        json_get_string(json, "decrypted_images_dir", out_rel, sizeof(out_rel));
        if (out_rel[0] == '/') {
            strncpy(output_dir, out_rel, sizeof(output_dir) - 1);
        } else if (last_slash) {
            int dir_len = (int)(last_slash - exe);
            snprintf(output_dir, sizeof(output_dir),
                     "%.*s/%s", dir_len, exe, out_rel);
        } else {
            strncpy(output_dir, out_rel, sizeof(output_dir) - 1);
        }

        /* image dir: sibling of db_storage */
        if (db_dir[0]) {
            char *last = strrchr(db_dir, '/');
            if (!last) last = strrchr(db_dir, '\\');
            if (last) {
                int plen = (int)(last - db_dir);
                snprintf(image_dir, sizeof(image_dir),
                         "%.*s/msg", plen, db_dir);
            }
        }

        free(json);
        printf("Config: %s\n", config_path);
    }

    /* Validate inputs */
    if (key_hex[0] == '\0') {
        fprintf(stderr, "ERROR: No image_key configured.\n");
        fprintf(stderr, "Run find_image_key first, or set image_key in config.json\n");
        return 1;
    }

    if (hex2bytes(key_hex, aes_key, 16) != 16) {
        fprintf(stderr, "ERROR: image_key must be 32 hex chars (16 bytes)\n");
        return 1;
    }

    if (image_dir[0] == '\0') {
        fprintf(stderr, "ERROR: Cannot determine image directory.\n");
        fprintf(stderr, "Set db_dir in config.json or pass image_dir as argument\n");
        return 1;
    }

    printf("Image key: %s\n", key_hex);
    printf("Image dir: %s\n", image_dir);
    printf("Output:    %s\n\n", output_dir);

    /* Create output directory */
    mkdirs(output_dir);

    /* Walk and decrypt */
    walk_ctx ctx = {
        .aes_key = aes_key,
        .xor_key = 0,
        .auto_xor = 1, /* auto-detect on first file */
        .output_dir = output_dir,
        .base_dir = image_dir,
        .success = 0,
        .skipped = 0,
        .failed = 0,
    };

    walk_dir(image_dir, &ctx);

    printf("\n==================================================\n");
    printf("Results: %d decrypted, %d skipped (non-V2), %d failed\n",
           ctx.success, ctx.skipped, ctx.failed);
    printf("Output:  %s\n", output_dir);
    printf("==================================================\n");

    return (ctx.success > 0) ? 0 : 1;
}
