#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init (void);

void check_address (void *addr);
struct lock syscall_lock;
int g_fd_nr;

typedef int pid_t;

struct fd_list_elem {
    int fd;
    struct list_elem elem;
    struct file *file_ptr;
};

void SyS_halt (void);
void SyS_exit (int status);
pid_t SyS_fork (const char *thread_name);
int SyS_exec (const char *cmd_line);
int SyS_wait (pid_t pid);
bool SyS_create (const char *file, unsigned initial_size);
bool SyS_remove (const char *file);
int SyS_open (const char *file);
int SyS_filesize (int fd);
int SyS_read (int fd, void *buffer, unsigned size);
int SyS_write(int fd, const void *buffer, unsigned size);
void SyS_seek (int fd, unsigned position);
unsigned SyS_tell (int fd);
void SyS_close (int fd);

#endif /* userprog/syscall.h */
