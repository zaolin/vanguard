#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/reboot.h>
#include <sys/reboot.h>

int main() {
    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    
    const char *devs[] = {"/dev/vda", "/dev/vdb", "/dev/sda", "/dev/sdb"};
    int mounted = 0;
    for (int i = 0; i < 4; i++) {
        struct stat st;
        if (stat(devs[i], &st) == 0) {
            FILE *f = fopen(devs[i], "r");
            if (f) {
                char magic[6] = {0};
                fread(magic, 1, 6, f);
                fclose(f);
                if (memcmp(magic, "LUKS", 4) != 0) {
                    mkdir("/cover", 0755);
                    if (mount(devs[i], "/cover", "ext4", 0, "sync") == 0) {
                        printf("cover: mounted %s at /cover (ext4)\n", devs[i]);
                        mounted = 1;
                        break;
                    }
                    if (mount(devs[i], "/cover", "vfat", 0, "sync") == 0) {
                        printf("cover: mounted %s at /cover (vfat)\n", devs[i]);
                        mounted = 1;
                        break;
                    }
                }
            }
        }
    }
    if (!mounted) {
        printf("cover: no cover disk found, using tmpfs\n");
        mkdir("/cover", 0755);
        mount("tmpfs", "/cover", "tmpfs", 0, NULL);
    }
    
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {"/init-go", NULL};
        char *envp[] = {"GOCOVERDIR=/cover", NULL};
        execve("/init-go", argv, envp);
        printf("cover: exec failed\n");
        _exit(1);
    }
    
    printf("cover: waiting for child (pid %d)\n", pid);
    int status;
    waitpid(pid, &status, 0);
    printf("cover: child exited with status %d\n", WEXITSTATUS(status));
    
    // List files in /cover
    DIR *d = opendir("/cover");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            printf("cover: file: %s\n", ent->d_name);
        }
        closedir(d);
    }
    
    sync();
    printf("cover: sync done, powering off\n");
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    
    return 0;
}
