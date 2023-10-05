#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "kernel/stdio.h"
#include "intrinsic.h"

typedef int pid_t;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static struct file *fd_to_file(int fd) {
	struct list_elem *e;
	struct thread *cur_thread = thread_current();
	for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e=list_next(e)) {
		struct fd_elem *tmp = list_entry(e, struct fd_elem, elem);
		if (fd == tmp->fd) {
			return tmp->file_ptr;
		}
	}
	return NULL;
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

// /* Reads a byte at user virtual address UADDR.
//  * UADDR must be below KERN_BASE.
//  * Returns the byte value if successful, -1 if a segfault
//  * occurred. */
// static int64_t
// get_user (const uint8_t *uaddr) {
//     int64_t result;
//     __asm __volatile (
//     "movabsq $done_get, %0\n"
//     "movzbq %1, %0\n"
//     "done_get:\n"
//     : "=&a" (result) : "m" (*uaddr));
//     return result;
// }

// /* Writes BYTE to user address UDST.
//  * UDST must be below KERN_BASE.
//  * Returns true if successful, false if a segfault occurred. */
// static bool
// put_user (uint8_t *udst, uint8_t byte) {
//     int64_t error_code;
//     __asm __volatile (
//     "movabsq $done_put, %0\n"
//     "movb %b2, %1\n"
//     "done_put:\n"
//     : "=&a" (error_code), "=m" (*udst) : "q" (byte));
//     return error_code != -1;
// }

static void check_vaddr (void *vaddr) {
	if (!vaddr || !is_user_vaddr(vaddr)) {
		sys_exit(-1);
	}
}

static void
sys_halt (void) {
	power_off();
}

void
sys_exit (int status) {
	struct thread *t = thread_current();
	t->exit_status = status;
	printf ("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

static pid_t
sys_fork (const char *thread_name){
	check_vaddr(thread_name);
	struct thread *t = thread_current();
	pid_t child_pid = process_fork(thread_name, NULL);

	if (child_pid == TID_ERROR) {
		return TID_ERROR;
	}

	struct thread *child_thread;
	struct list_elem * e;
	for (e = list_begin (&t->children); e != list_end (&t->children); e = list_next (e)) {
		child_thread = list_entry(e, struct thread, child_elem);
		if (child_thread->tid == child_pid) {
			break;
		}
	}
	if (e == list_end(&t->children)) {
		return TID_ERROR;
	}

	sema_down(&child_thread->fork_sema);
	if (child_thread->exit_status == TID_ERROR) {
		return TID_ERROR;
	}

	return child_pid;
}

static int
sys_exec (const char *file) {
	check_vaddr(file);
	char *file_copy = malloc(strlen(file) + 1);
	strlcpy(file_copy, file, strlen(file) + 1);
	int ret = process_exec(file_copy);
	free(file_copy);
	if (ret == -1) {
		sys_exit(ret);
	}
	NOT_REACHED();
}

static int
sys_wait (pid_t pid) {
	return process_wait(pid);
}

static bool
sys_create (const char *file, unsigned initial_size) {
	check_vaddr(file);
	lock_acquire(&filesys_lock);
	bool ret = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return ret;
}

static bool
sys_remove (const char *file) {
	check_vaddr(file);
	lock_acquire(&filesys_lock);
	bool ret = filesys_remove(file);
	lock_release(&filesys_lock);
	return ret;
}

static int
sys_open (const char *file) {
	check_vaddr(file);
	struct thread * cur_thread = thread_current();
	lock_acquire(&filesys_lock);
	struct file *file_ptr = filesys_open(file);
	lock_release(&filesys_lock);
	if (!file_ptr) {
		return -1;
	}
	if (!strcmp(file, cur_thread->name)) {
		file_deny_write(file_ptr);
	}
	struct fd_elem *file_elem = (struct fd_elem *)malloc(sizeof (struct fd_elem));
	file_elem->fd = cur_thread->next_fd++;
	file_elem->file_ptr = file_ptr;
	list_push_back(&cur_thread->fdt, &file_elem->elem);
	return file_elem->fd;
}

static int
sys_filesize (int fd) {
	struct thread * cur_thread = thread_current();
	struct file *file_ptr = fd_to_file(fd);
	int ret = file_ptr ? file_length(file_ptr) : -1;
	return ret;
}

static int
sys_read (int fd, void *buffer, unsigned size) {
	check_vaddr(buffer);
	int cnt = 0;
	if (fd == 0) {
		lock_acquire(&filesys_lock);
		cnt = input_getc();
		lock_release(&filesys_lock);
		return cnt;
	}
	if (fd == 1) {
		return -1;
	}
	struct thread * cur_thread = thread_current();
	struct file *file_ptr = fd_to_file(fd);
	if (!file_ptr) {
		return -1;
	}
	lock_acquire(&filesys_lock);
	cnt = file_read(file_ptr, buffer, size);
	lock_release(&filesys_lock);
	return cnt;
}

static int
sys_write (int fd, const void *buffer, unsigned size) {
	check_vaddr(buffer);
	int cnt = 0;
	if (fd == 0) {
		return -1;
	}
	if (fd == 1) {
		lock_acquire(&filesys_lock);
		putbuf(buffer, size);
		lock_release(&filesys_lock);
		return size;
	}
	struct thread *cur_thread = thread_current();
	struct file *file_ptr = fd_to_file(fd);
	if (!file_ptr) {
		return -1;
	}
	lock_acquire(&filesys_lock);
	cnt = file_write(file_ptr, buffer, size);
	lock_release(&filesys_lock);
	return cnt;
}

static void
sys_seek (int fd, unsigned position) {
	struct thread *cur_thread = thread_current();
	struct file *file_ptr = fd_to_file(fd);
	if (!file_ptr) {
		return;
	}
	lock_acquire(&filesys_lock);
	file_seek(file_ptr, position);
	lock_release(&filesys_lock);
}

static unsigned
sys_tell (int fd) {
	struct thread *cur_thread = thread_current();
	struct file *file_ptr = fd_to_file(fd);
	int cnt = 0;
	if (!file_ptr) {
		sys_exit(-1);
	}
	cnt = file_tell(file_ptr);
	return cnt;
}

static void
sys_close (int fd) {
	struct thread *cur_thread = thread_current();
	struct list_elem *e;
	struct fd_elem *file_elem;
	for (e = list_begin(&cur_thread->fdt); e != list_end(&cur_thread->fdt); e = list_next(e)) {
		file_elem = list_entry(e, struct fd_elem, elem);
		if (fd == file_elem->fd) {
			break;
		}
	}
	if (e == list_end(&cur_thread->fdt)) {
		sys_exit(-1);
	}
	list_remove(e);
	lock_acquire(&filesys_lock);
	file_close(file_elem->file_ptr);
	lock_release(&filesys_lock);
	free(file_elem);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	memcpy(&thread_current()->parent_if, f, sizeof(struct intr_frame));
	switch (f->R.rax) {
		case SYS_HALT:
			sys_halt();
			break;
		case SYS_EXIT:
			sys_exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = sys_fork(f->R.rdi);
			break;
		case SYS_EXEC:
			f->R.rax = sys_exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = sys_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = sys_create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = sys_remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = sys_open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = sys_filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			sys_seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = sys_tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			sys_close(f->R.rdi);
			break;
		default:
			printf("system call!\n");
			thread_exit();
			break;
	}
}
