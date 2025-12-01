#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>

int main() {
    pid_t pid = getpid();
    pid_t ppid = getppid();
    uid_t uid = getuid();
    gid_t gid = getgid();
    int priority = getpriority(PRIO_PROCESS, 0);

    printf("╔════════════════════════════════╗\n");
    printf("║   PROCESSUS TEST (PCB)         ║\n");
    printf("╠════════════════════════════════╣\n");
    printf("║ PID      : %-19d ║\n", pid);
    printf("║ PPID     : %-19d ║\n", ppid);
    printf("║ UID      : %-19d ║\n", uid);
    printf("║ GID      : %-19d ║\n", gid);
    printf("║ Priorité : %-19d ║\n", priority);
    printf("╚════════════════════════════════╝\n\n");

    // Sauvegarder le PID pour le module
    FILE *f = fopen("/tmp/pid_to_hide.txt", "w");
    if (f) {
        fprintf(f, "%d", pid);
        fclose(f);
        printf("✓ PID sauvegardé dans /tmp/pid_to_hide.txt\n");
    }

    printf("✓ Processus actif - Visible dans ps/top\n\n");

    // Boucle infinie
    while (1) {
        sleep(5);
    }

    return 0;
}
