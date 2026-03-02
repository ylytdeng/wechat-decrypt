/*
 * find_image_key.c — macOS V2 image AES key scanner
 *
 * Scans WeChat process memory for the V2 image decryption key.
 * The key is only transiently present in memory while WeChat is
 * actively displaying images — run this IMMEDIATELY after viewing
 * images in WeChat (e.g. Moments).
 *
 * Build:
 *   cc -O3 -o find_image_key find_image_key.c -framework Security
 *
 * Usage:
 *   sudo ./find_image_key                    # auto-find V2 files from config.json
 *   sudo ./find_image_key <ct_block_hex>     # manual CT block
 *
 * The key is printed as a hex string. If config.json exists, also
 * writes the key to the "image_key" field.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <CommonCrypto/CommonCryptor.h>

#define MAX_PATH 4096
#define V2_MAGIC "\x07\x08V2\x08\x07"
#define V2_MAGIC_LEN 6

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

static void bytes2hex(const unsigned char *data, int len, char *out) {
    for (int i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", data[i]);
    out[len * 2] = '\0';
}

/* ---- Config.json parsing (minimal) ---- */

/* Extract a JSON string value for a given key from a buffer */
static int json_get_string(const char *json, const char *key,
                           char *value, int maxlen) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0;
    p = strchr(p + strlen(pattern), '"');
    if (!p) return 0;
    p++; /* skip opening quote */
    const char *end = strchr(p, '"');
    if (!end) return 0;
    int len = (int)(end - p);
    if (len >= maxlen) len = maxlen - 1;
    memcpy(value, p, len);
    value[len] = '\0';
    return 1;
}

/* Write image_key into config.json */
static void config_write_image_key(const char *config_path, const char *key_hex) {
    FILE *f = fopen(config_path, "r");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz + 256);
    size_t rd = fread(buf, 1, sz, f);
    buf[rd] = '\0';
    fclose(f);

    /* Find "image_key": "..." and replace the value */
    char *p = strstr(buf, "\"image_key\"");
    if (p) {
        /* Find the value string */
        char *q = strchr(p + 11, '"');
        if (q) {
            q++; /* start of old value */
            char *r = strchr(q, '"');
            if (r) {
                /* Build new file content */
                FILE *out = fopen(config_path, "w");
                if (out) {
                    fwrite(buf, 1, q - buf, out);
                    fputs(key_hex, out);
                    fputs(r, out); /* rest including closing quote */
                    fclose(out);
                    printf("  Updated %s with image_key\n", config_path);
                    free(buf);
                    return;
                }
            }
        }
    }

    /* No image_key field found — insert before last } */
    char *last_brace = strrchr(buf, '}');
    if (last_brace) {
        FILE *out = fopen(config_path, "w");
        if (out) {
            fwrite(buf, 1, last_brace - buf, out);
            fprintf(out, ",\n    \"image_key\": \"%s\"\n}", key_hex);
            fclose(out);
            printf("  Updated %s with image_key\n", config_path);
        }
    }
    free(buf);
}

/* ---- V2 .dat file discovery ---- */

static int find_v2_ct_block(const char *base_dir, unsigned char *ct_block) {
    /* Walk the directory tree looking for V2 .dat files */
    DIR *d = opendir(base_dir);
    if (!d) return 0;

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;

        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s/%s", base_dir, ent->d_name);

        struct stat st;
        if (stat(path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            if (find_v2_ct_block(path, ct_block)) {
                closedir(d);
                return 1;
            }
        } else if (S_ISREG(st.st_mode)) {
            size_t nlen = strlen(ent->d_name);
            if (nlen < 5 || strcmp(ent->d_name + nlen - 4, ".dat") != 0)
                continue;

            FILE *f = fopen(path, "rb");
            if (!f) continue;

            unsigned char hdr[6];
            if (fread(hdr, 1, 6, f) == 6 && memcmp(hdr, V2_MAGIC, 6) == 0) {
                fseek(f, 15, SEEK_SET);
                if (fread(ct_block, 1, 16, f) == 16) {
                    char hex[33];
                    bytes2hex(ct_block, 16, hex);
                    printf("CT block: %s\n", hex);
                    printf("From: ...%s\n\n",
                           strlen(path) > 60 ? path + strlen(path) - 60 : path);
                    fclose(f);
                    closedir(d);
                    return 1;
                }
            }
            fclose(f);
        }
    }
    closedir(d);
    return 0;
}

/* ---- Process discovery ---- */

static int get_wechat_pids(pid_t *pids, int max_pids) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    sysctl(mib, 4, NULL, &size, NULL, 0);
    struct kinfo_proc *procs = malloc(size);
    sysctl(mib, 4, procs, &size, NULL, 0);
    int nprocs = (int)(size / sizeof(struct kinfo_proc));
    int count = 0;
    for (int i = 0; i < nprocs && count < max_pids; i++) {
        if (strstr(procs[i].kp_proc.p_comm, "WeChat"))
            pids[count++] = procs[i].kp_proc.p_pid;
    }
    free(procs);
    return count;
}

/* ---- AES test ---- */

static inline int try_key(const unsigned char *key, const unsigned char *ct) {
    unsigned char pt[16];
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(
        kCCDecrypt, kCCAlgorithmAES128, kCCOptionECBMode,
        key, 16, NULL, ct, 16, pt, 16, &moved);
    if (st != kCCSuccess) return 0;
    /* FFD8FF + valid JPEG marker (E0-EF, DB, C0-C3, C4, FE, etc.) */
    return (pt[0] == 0xFF && pt[1] == 0xD8 && pt[2] == 0xFF &&
            (pt[3] >= 0xC0 || pt[3] == 0x00));
}

/* ---- Memory scanning ---- */

static int scan_pid(pid_t pid, const unsigned char *ct, unsigned char *found_key) {
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        printf("  PID %d: task_for_pid failed (%d)\n", pid, kr);
        return 0;
    }

    mach_vm_address_t addr = 0;
    mach_vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count;
    mach_port_t obj;

    long regions = 0;
    long long total_bytes = 0, tests = 0;

    while (1) {
        count = VM_REGION_BASIC_INFO_COUNT_64;
        kr = mach_vm_region(task, &addr, &rsize, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &count, &obj);
        if (kr != KERN_SUCCESS) break;
        regions++;

        if ((info.protection & VM_PROT_READ) && rsize > 0 &&
            rsize < 200 * 1024 * 1024) {
            vm_offset_t data;
            mach_msg_type_number_t data_cnt;
            kr = mach_vm_read(task, addr, rsize, &data, &data_cnt);
            if (kr == KERN_SUCCESS) {
                unsigned char *buf = (unsigned char *)data;
                total_bytes += data_cnt;

                /* Method 1: every 16-byte aligned position (raw binary) */
                for (mach_msg_type_number_t j = 0; j + 16 <= data_cnt; j += 16) {
                    tests++;
                    if (try_key(buf + j, ct)) {
                        memcpy(found_key, buf + j, 16);
                        char hex[33];
                        bytes2hex(found_key, 16, hex);
                        printf("\n==================================================\n");
                        printf("*** FOUND KEY: %s ***\n", hex);
                        printf("  ASCII: ");
                        for (int k = 0; k < 16; k++)
                            putchar((buf[j+k] >= 0x20 && buf[j+k] < 0x7f)
                                        ? buf[j+k] : '.');
                        printf("\n  PID %d, addr=0x%llx+0x%x\n", pid, addr, j);
                        printf("==================================================\n");
                        mach_vm_deallocate(mach_task_self(), data, data_cnt);
                        return 1;
                    }
                }

                /* Method 2: ASCII [a-z0-9]{16+} patterns */
                int run = 0, run_start = 0;
                for (mach_msg_type_number_t j = 0; j <= data_cnt; j++) {
                    int is_hex = (j < data_cnt) &&
                        ((buf[j] >= 'a' && buf[j] <= 'z') ||
                         (buf[j] >= '0' && buf[j] <= '9'));
                    if (is_hex) {
                        if (run == 0) run_start = j;
                        run++;
                    } else {
                        if (run >= 16) {
                            for (int k = run_start; k + 16 <= run_start + run; k++) {
                                /* Skip if this position was already tested as aligned */
                                if (k % 16 == 0) continue;
                                tests++;
                                if (try_key(buf + k, ct)) {
                                    memcpy(found_key, buf + k, 16);
                                    char hex[33];
                                    bytes2hex(found_key, 16, hex);
                                    printf("\n==================================================\n");
                                    printf("*** FOUND KEY: %s ***\n", hex);
                                    printf("  ASCII: %.32s\n", buf + run_start);
                                    printf("  PID %d, addr=0x%llx+0x%x\n", pid, addr, k);
                                    printf("==================================================\n");
                                    mach_vm_deallocate(mach_task_self(), data, data_cnt);
                                    return 1;
                                }
                            }
                        }
                        run = 0;
                    }
                }

                mach_vm_deallocate(mach_task_self(), data, data_cnt);
            }
        }

        addr += rsize;
        if (regions % 500 == 0) {
            printf("  [%ld regions, %lld MB, %lld tests]\r",
                   regions, total_bytes / (1024 * 1024), tests);
            fflush(stdout);
        }
    }

    printf("  PID %d: %ld regions, %lld MB, %lld tests          \n",
           pid, regions, total_bytes / (1024 * 1024), tests);
    return 0;
}

/* ---- Main ---- */

int main(int argc, char *argv[]) {
    unsigned char ct_block[16];
    int have_ct = 0;

    printf("=== WeChat V2 Image Key Scanner (macOS) ===\n\n");

    if (getuid() != 0) {
        fprintf(stderr, "ERROR: Run with sudo!\n");
        return 1;
    }

    /* Try to get CT block from argument */
    if (argc >= 2) {
        if (hex2bytes(argv[1], ct_block, 16) == 16) {
            char hex[33];
            bytes2hex(ct_block, 16, hex);
            printf("CT block (from arg): %s\n\n", hex);
            have_ct = 1;
        }
    }

    /* Try to read config.json for image_dir */
    char config_path[MAX_PATH];
    char db_dir[MAX_PATH] = "";

    /* Find config.json relative to executable */
    const char *exe = argv[0];
    const char *last_slash = strrchr(exe, '/');
    if (last_slash) {
        int dir_len = (int)(last_slash - exe);
        snprintf(config_path, sizeof(config_path), "%.*s/config.json", dir_len, exe);
    } else {
        strcpy(config_path, "config.json");
    }

    FILE *cf = fopen(config_path, "r");
    if (cf) {
        fseek(cf, 0, SEEK_END);
        long sz = ftell(cf);
        fseek(cf, 0, SEEK_SET);
        char *json = malloc(sz + 1);
        fread(json, 1, sz, cf);
        json[sz] = '\0';
        fclose(cf);
        json_get_string(json, "db_dir", db_dir, sizeof(db_dir));
        free(json);
    }

    /* Auto-discover CT block from V2 .dat files */
    if (!have_ct && db_dir[0]) {
        /* Image cache is at sibling "msg" directory of db_storage */
        char image_dir[MAX_PATH];
        char *last = strrchr(db_dir, '/');
        if (!last) last = strrchr(db_dir, '\\');
        if (last) {
            int plen = (int)(last - db_dir);
            snprintf(image_dir, sizeof(image_dir), "%.*s/msg", plen, db_dir);
        } else {
            snprintf(image_dir, sizeof(image_dir), "%s/../msg", db_dir);
        }
        printf("Scanning for V2 files in: %s\n", image_dir);
        have_ct = find_v2_ct_block(image_dir, ct_block);
    }

    if (!have_ct) {
        fprintf(stderr, "ERROR: No V2 .dat file found.\n");
        fprintf(stderr, "Usage: sudo %s [ct_block_hex]\n", argv[0]);
        fprintf(stderr, "  or configure db_dir in config.json\n");
        return 1;
    }

    /* Find WeChat processes */
    pid_t pids[64];
    int npids = get_wechat_pids(pids, 64);
    if (npids == 0) {
        fprintf(stderr, "ERROR: No WeChat processes found!\n");
        return 1;
    }
    printf("WeChat processes: %d PIDs\n\n", npids);

    /* Scan all processes */
    unsigned char found_key[16];
    for (int i = 0; i < npids; i++) {
        printf("Scanning PID %d...\n", pids[i]);
        if (scan_pid(pids[i], ct_block, found_key)) {
            char key_hex[33];
            bytes2hex(found_key, 16, key_hex);
            printf("\nYour V2 image key: %s\n", key_hex);

            /* Update config.json */
            config_write_image_key(config_path, key_hex);
            return 0;
        }
    }

    printf("\n*** KEY NOT FOUND ***\n");
    printf("TIP: View images in WeChat Moments, then run IMMEDIATELY!\n");
    printf("The key only exists in memory while WeChat is displaying images.\n");
    return 1;
}
