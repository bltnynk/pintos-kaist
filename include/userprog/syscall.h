#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct fd_elem {
    int fd;
    struct list_elem elem;
    struct file *file_ptr;
};

struct lock filesys_lock;
void sys_exit(int);
void syscall_init (void);
#endif /* userprog/syscall.h */
