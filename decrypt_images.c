/*
 * decrypt_images.c — WeChat V2 image batch decryptor (multi-key)
 *
 * Decrypts all V2 encrypted .dat files in the WeChat image cache.
 * Supports multiple keys via image_keys.json (CT block → AES key mapping).
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
 *   ./decrypt_images                                   # auto from config + image_keys.json
 *   ./decrypt_images <key_hex> <image_dir> <out_dir>   # single-key manual
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <CommonCrypto/CommonCryptor.h>

#define MAX_PATH    4096
#define V2_MAGIC    "\x07\x08V2\x08\x07"
#define V2_MAGIC_LEN 6
#define HEADER_SIZE 15
#define MAX_KEYS    64

/* ---- Key mapping: CT block hex → AES key ---- */
typedef struct {
    unsigned char ct[16];   /* CT block 0 pattern */
    unsigned char key[16];  /* AES key for this pattern */
} key_map_t;

static key_map_t key_map[MAX_KEYS];
static int       n_keys = 0;

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

static void bytes2hex(const unsigned char *d, int n, char *out) {
    for (int i = 0; i < n; i++) sprintf(out + i*2, "%02x", d[i]);
    out[n*2] = '\0';
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

/* Load image_keys.json: { "ct_hex": "key_hex", ... } */
static int load_key_map(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *json = malloc(sz + 1);
    fread(json, 1, sz, f);
    json[sz] = '\0';
    fclose(f);

    /* Simple parser: find all "32hex": "32hex" pairs */
    const char *p = json;
    while ((p = strchr(p, '"')) && n_keys < MAX_KEYS) {
        p++;
        const char *end = strchr(p, '"');
        if (!end) break;
        int klen = (int)(end - p);
        if (klen != 32) { p = end + 1; continue; }

        char ct_hex[33];
        memcpy(ct_hex, p, 32);
        ct_hex[32] = '\0';
        p = end + 1;

        /* Find next quoted string (the value) */
        p = strchr(p, '"');
        if (!p) break;
        p++;
        end = strchr(p, '"');
        if (!end) break;
        int vlen = (int)(end - p);
        if (vlen != 32) { p = end + 1; continue; }

        char key_hex[33];
        memcpy(key_hex, p, 32);
        key_hex[32] = '\0';
        p = end + 1;

        hex2bytes(ct_hex, key_map[n_keys].ct, 16);
        hex2bytes(key_hex, key_map[n_keys].key, 16);
        n_keys++;
    }
    free(json);
    return n_keys;
}

/* Find AES key for a given CT block */
static const unsigned char *find_key_for_ct(const unsigned char *ct) {
    for (int i = 0; i < n_keys; i++)
        if (memcmp(key_map[i].ct, ct, 16) == 0) return key_map[i].key;
    return NULL;
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

/* Auto-detect XOR key */
static unsigned char detect_xor_key(const unsigned char *xor_data, size_t xor_size) {
    if (xor_size == 0) return 0;
    unsigned char candidates[] = {0x80, 0xDC, 0x00};
    for (int i = 0; i < (int)(sizeof(candidates)/sizeof(candidates[0])); i++) {
        unsigned char test = xor_data[0] ^ candidates[i];
        if (test != 0x00 || candidates[i] == 0x00)
            return candidates[i];
    }
    return 0x80;
}

/* ---- Decrypt one V2 file ---- */

static int decrypt_v2_file(const char *input_path, const char *output_dir,
                           const char *rel_path, const unsigned char *aes_key,
                           unsigned char xor_key, int auto_xor,
                           int *out_xor_detected) {
    FILE *fin = fopen(input_path, "rb");
    if (!fin) return -1;

    unsigned char header[HEADER_SIZE];
    if (fread(header, 1, HEADER_SIZE, fin) != HEADER_SIZE) {
        fclose(fin); return -1;
    }
    if (memcmp(header, V2_MAGIC, V2_MAGIC_LEN) != 0) {
        fclose(fin); return -2;
    }

    uint32_t aes_size, xor_size;
    memcpy(&aes_size, header + 6, 4);
    memcpy(&xor_size, header + 10, 4);

    uint32_t aes_ct_size = ((aes_size + 15) / 16) * 16;

    unsigned char *aes_ct = malloc(aes_ct_size);
    if (!aes_ct) { fclose(fin); return -1; }
    size_t rd = fread(aes_ct, 1, aes_ct_size, fin);
    if (rd < aes_ct_size) memset(aes_ct + rd, 0, aes_ct_size - rd);

    unsigned char *xor_data = NULL;
    if (xor_size > 0) {
        xor_data = malloc(xor_size);
        if (!xor_data) { free(aes_ct); fclose(fin); return -1; }
        rd = fread(xor_data, 1, xor_size, fin);
        if (rd < xor_size) memset(xor_data + rd, 0, xor_size - rd);
    }
    fclose(fin);

    /* If multi-key mode: look up key by CT block 0 */
    if (!aes_key && aes_ct_size >= 16) {
        aes_key = find_key_for_ct(aes_ct);
        if (!aes_key) {
            free(aes_ct); free(xor_data); return -5; /* no key for this pattern */
        }
    }
    if (!aes_key) { free(aes_ct); free(xor_data); return -5; }

    unsigned char *aes_pt = malloc(aes_ct_size);
    if (!aes_pt) { free(aes_ct); free(xor_data); return -1; }

    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(
        kCCDecrypt, kCCAlgorithmAES128, kCCOptionECBMode,
        aes_key, 16, NULL,
        aes_ct, aes_ct_size, aes_pt, aes_ct_size, &moved);
    free(aes_ct);

    if (st != kCCSuccess) {
        free(aes_pt); free(xor_data); return -3;
    }

    if (auto_xor && xor_data && xor_size > 0) {
        xor_key = detect_xor_key(xor_data, xor_size);
        if (out_xor_detected) *out_xor_detected = xor_key;
    }

    if (xor_data && xor_size > 0) {
        for (uint32_t i = 0; i < xor_size; i++)
            xor_data[i] ^= xor_key;
    }

    const char *ext = detect_ext(aes_pt, aes_size);

    char out_path[MAX_PATH];
    char rel_noext[MAX_PATH];
    snprintf(rel_noext, sizeof(rel_noext), "%s", rel_path);
    char *dot = strrchr(rel_noext, '.');
    if (dot) *dot = '\0';
    snprintf(out_path, sizeof(out_path), "%s/%s%s", output_dir, rel_noext, ext);

    /* Skip if already decrypted */
    struct stat st_out;
    if (stat(out_path, &st_out) == 0 && st_out.st_size > 0) {
        free(aes_pt); free(xor_data);
        return 1; /* already exists */
    }

    char parent[MAX_PATH];
    snprintf(parent, sizeof(parent), "%s", out_path);
    char *last_slash = strrchr(parent, '/');
    if (last_slash) { *last_slash = '\0'; mkdirs(parent); }

    FILE *fout = fopen(out_path, "wb");
    if (!fout) { free(aes_pt); free(xor_data); return -4; }

    fwrite(aes_pt, 1, aes_size, fout);
    if (xor_data && xor_size > 0) fwrite(xor_data, 1, xor_size, fout);

    fclose(fout);
    free(aes_pt);
    free(xor_data);
    return 0;
}

/* ---- Directory walking ---- */

typedef struct {
    const unsigned char *fallback_key; /* single key from config.json (or NULL) */
    int multi_key;                     /* 1 if using image_keys.json */
    unsigned char xor_key;
    int auto_xor;
    const char *output_dir;
    const char *base_dir;
    int success;
    int skipped;
    int existed;                       /* already decrypted */
    int no_key;                        /* V2 files with no matching key */
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

            const char *rel = path + strlen(ctx->base_dir);
            if (*rel == '/') rel++;

            int xor_detected = -1;
            /* In multi-key mode, pass NULL as key — decrypt_v2_file looks it up */
            const unsigned char *key = ctx->multi_key ? NULL : ctx->fallback_key;
            int ret = decrypt_v2_file(path, ctx->output_dir, rel,
                                       key, ctx->xor_key,
                                       ctx->auto_xor, &xor_detected);

            if (ret == 0) {
                ctx->success++;
                if (ctx->auto_xor && xor_detected >= 0) {
                    ctx->xor_key = (unsigned char)xor_detected;
                    ctx->auto_xor = 0;
                    printf("  Auto-detected XOR key: 0x%02X\n", ctx->xor_key);
                }
                if (ctx->success <= 5 || ctx->success % 1000 == 0) {
                    printf("  [%d] %s\n", ctx->success, rel);
                }
            } else if (ret == 1) {
                ctx->existed++;
            } else if (ret == -2) {
                ctx->skipped++;
            } else if (ret == -5) {
                ctx->no_key++;
            } else {
                ctx->failed++;
                if (ctx->failed <= 5)
                    printf("  FAIL(%d): %s\n", ret, rel);
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
    int have_single_key = 0;

    printf("=== WeChat V2 Image Decryptor ===\n\n");

    /* Determine exe directory for config file lookup */
    char exe_dir[MAX_PATH] = ".";
    const char *last_slash = strrchr(argv[0], '/');
    if (last_slash) {
        int len = (int)(last_slash - argv[0]);
        snprintf(exe_dir, sizeof(exe_dir), "%.*s", len, argv[0]);
    }

    if (argc >= 4) {
        /* Manual single-key mode */
        strncpy(key_hex, argv[1], sizeof(key_hex) - 1);
        strncpy(image_dir, argv[2], sizeof(image_dir) - 1);
        strncpy(output_dir, argv[3], sizeof(output_dir) - 1);
        have_single_key = 1;
    } else {
        /* Load image_keys.json first (multi-key) */
        char keys_path[MAX_PATH];
        snprintf(keys_path, sizeof(keys_path), "%s/image_keys.json", exe_dir);
        int loaded = load_key_map(keys_path);
        if (loaded > 0)
            printf("Loaded %d key mappings from %s\n", loaded, keys_path);

        /* Read config.json for paths (and fallback single key) */
        char cfg_path[MAX_PATH];
        snprintf(cfg_path, sizeof(cfg_path), "%s/config.json", exe_dir);
        FILE *cf = fopen(cfg_path, "r");
        if (!cf) {
            fprintf(stderr, "ERROR: Cannot open %s\n", cfg_path);
            return 1;
        }

        fseek(cf, 0, SEEK_END);
        long sz = ftell(cf);
        fseek(cf, 0, SEEK_SET);
        char *json = malloc(sz + 1);
        fread(json, 1, sz, cf);
        json[sz] = '\0';
        fclose(cf);

        if (json_get_string(json, "image_key", key_hex, sizeof(key_hex)))
            have_single_key = 1;

        char db_dir[MAX_PATH] = "";
        json_get_string(json, "db_dir", db_dir, sizeof(db_dir));

        char out_rel[MAX_PATH] = "decrypted_images";
        json_get_string(json, "decrypted_images_dir", out_rel, sizeof(out_rel));
        if (out_rel[0] == '/')
            strncpy(output_dir, out_rel, sizeof(output_dir) - 1);
        else
            snprintf(output_dir, sizeof(output_dir), "%s/%s", exe_dir, out_rel);

        if (db_dir[0]) {
            char *s = strrchr(db_dir, '/');
            if (!s) s = strrchr(db_dir, '\\');
            if (s) {
                int plen = (int)(s - db_dir);
                snprintf(image_dir, sizeof(image_dir),
                         "%.*s/msg", plen, db_dir);
            }
        }
        free(json);
    }

    /* Parse single key if available (used as fallback or sole key) */
    if (have_single_key && key_hex[0]) {
        if (hex2bytes(key_hex, aes_key, 16) == 16) {
            /* If no image_keys.json loaded, add single key to key_map
             * by discovering its CT block at runtime */
        } else {
            have_single_key = 0;
        }
    }

    if (n_keys == 0 && !have_single_key) {
        fprintf(stderr, "ERROR: No keys available.\n");
        fprintf(stderr, "Run find_image_key first, or set image_key in config.json\n");
        return 1;
    }

    if (image_dir[0] == '\0') {
        fprintf(stderr, "ERROR: Cannot determine image directory.\n");
        return 1;
    }

    printf("Mode:      %s\n", n_keys > 0 ? "multi-key" : "single-key");
    if (n_keys > 0) printf("Keys:      %d pattern→key mappings\n", n_keys);
    if (have_single_key) printf("Fallback:  %s\n", key_hex);
    printf("Image dir: %s\n", image_dir);
    printf("Output:    %s\n\n", output_dir);

    mkdirs(output_dir);

    walk_ctx ctx = {
        .fallback_key = have_single_key ? aes_key : NULL,
        .multi_key    = (n_keys > 0),
        .xor_key      = 0,
        .auto_xor     = 1,
        .output_dir   = output_dir,
        .base_dir     = image_dir,
        .success      = 0,
        .skipped      = 0,
        .existed      = 0,
        .no_key       = 0,
        .failed       = 0,
    };

    walk_dir(image_dir, &ctx);

    printf("\n==================================================\n");
    printf("Results:\n");
    printf("  Decrypted:  %d\n", ctx.success);
    printf("  Existed:    %d (already decrypted, skipped)\n", ctx.existed);
    printf("  No key:     %d (run find_image_key to discover more keys)\n", ctx.no_key);
    printf("  Skipped:    %d (non-V2)\n", ctx.skipped);
    printf("  Failed:     %d\n", ctx.failed);
    printf("Output: %s\n", output_dir);
    printf("==================================================\n");

    return (ctx.success > 0) ? 0 : 1;
}
