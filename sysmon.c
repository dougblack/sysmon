
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <linux/kprobes.h>

#include <asm/current.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");

#define MODULE_NAME "[sysmon] "

#define uid_name "sysmon_uid"
#define toggle_name "sysmon_toggle"
#define log_name "sysmon_log"

#define MAX_BUFFER_SIZE 1024

/* All of the syscalls we're interested */
static char *probe_names[] = {"sys_access", "sys_brk", "sys_chdir", "sys_chmod", "sys_clone", "sys_close", "sys_dup", "sys_dup2", "sys_execve", "sys_exit_group", "sys_fcntl", "sys_fork", "sys_getdents", "sys_getpid", "sys_gettid", "sys_ioctl", "sys_lseek", "sys_mkdir", "sys_mmap", "sys_munmap", "sys_open", "sys_pipe", "sys_read", "sys_rmdir", "sys_select", "sys_stat", "sys_fstat", "sys_lstat", "sys_wait4", "sys_write"};

/* The KPROBE! */
static struct kprobe probes[30];

struct proc_dir_entry *uid_entry;
struct proc_dir_entry *toggle_entry;
struct proc_dir_entry *log_entry;

static int toggle = 0;
static int uid = 0;

/* Called before each syscall */
static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
   int ret = 0;
   if (current->uid != uid)
      return 0;
   printk(KERN_INFO MODULE_NAME "[%s] %lu %d %d args 0x%lu '%lu' %d\n", kp->symbol_name, regs->rax, current->pid, current->tgid, (uintptr_t) regs->rdi, regs->rdi, (int) regs->rsi);
   return ret;
}

/* Called after each syscall */
static void sysmon_intercept_after(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{

}

/* Read current uid */
int uid_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
   int ret_length;
   if (offset > 0) {
      ret_length = 0; 
   } else {
      ret_length = sprintf(buffer, "%d\n", uid);
   }
   return ret_length;
}

/* Set current uid */
int uid_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
   char *uid_buffer[MAX_BUFFER_SIZE];

   if (copy_from_user(uid_buffer, buffer, count)) {
      return -EFAULT;
   }

   sscanf((const char*) uid_buffer, "%d", &uid);
   printk(KERN_INFO "uid is %d", uid);

   return count;
}

/* Read enabled/disabled */
int toggle_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
   int ret_length;
   if (offset > 0) {
      ret_length = 0; 
   } else {
      ret_length = sprintf(buffer, "%d\n", toggle);
   }
   return ret_length;
}

/* Set enabled/disabled */
int toggle_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
   char *toggle_buffer[MAX_BUFFER_SIZE];

   if (copy_from_user(toggle_buffer, buffer, count)) {
      return -EFAULT;
   }

   sscanf((const char*) toggle_buffer, "%d", &toggle);
   printk(KERN_INFO "toggle is %d", toggle);

   return count;
}

/* Read the log */
int log_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
   int ret_length;
   if (offset > 0) {
      ret_length = 0; 
   } else {
      /* RETURN LOG HERE */
   }
   return ret_length;
}

/* Set up module */
int init_module()
{
   int i, ret;
   static struct kprobe *probe;

   printk(KERN_INFO MODULE_NAME "Initializing sysmon!\n");

   /* Set values of each kprobe in our kprobe array. */
   for (i = 0; i < 30; i++) {
      probe = &(probes[i]);
      probe->symbol_name = probe_names[i];
      probe->pre_handler = sysmon_intercept_before; 
      probe->post_handler = sysmon_intercept_after;

      if ((ret = register_kprobe(&(probes[i]))) < 0) {
         printk(KERN_ERR MODULE_NAME "[%s] register_kprobe failed; returned %d.\n", probe->symbol_name, ret);
         return -EFAULT;
      }
   }

   printk(KERN_INFO MODULE_NAME "added all the kprobes.\n");

   /* Create proc files */
   uid_entry = create_proc_entry(uid_name, 0600, NULL);
   toggle_entry = create_proc_entry(toggle_name, 0600, NULL);
   log_entry = create_proc_entry(log_name, 0600, NULL);
  
   if (uid_entry == NULL || toggle_entry == NULL || log_entry == NULL) {
      remove_proc_entry(uid_name, NULL);
      printk(KERN_INFO "/proc/%s removed\n", uid_name);
      remove_proc_entry(toggle_name, NULL);
      printk(KERN_INFO "/proc/%s removed\n", toggle_name);
      remove_proc_entry(log_name, NULL);
      printk(KERN_INFO "/proc/%s removed\n", log_name);
      printk(KERN_INFO MODULE_NAME "Couldn't make proc files so removed them.\n");
      return -EFAULT;
   }

   uid_entry->read_proc = uid_read;
   uid_entry->write_proc = uid_write;
   uid_entry->owner = THIS_MODULE;
   uid_entry->mode = S_IFREG | S_IRUGO;
   uid_entry->size = 37;

   toggle_entry->read_proc = toggle_read;
   toggle_entry->write_proc = toggle_write;
   toggle_entry->owner = THIS_MODULE;
   toggle_entry->mode = S_IFREG | S_IRUGO;
   toggle_entry->size = 37;

   log_entry->read_proc = log_read;
   log_entry->owner = THIS_MODULE;
   log_entry->mode = S_IFREG | S_IRUGO;
   log_entry->size = 37;
   printk(KERN_INFO MODULE_NAME "Done initializing sysmon.\n"); 
   return 0; 
}

/* Clean up module */
void cleanup_module()
{
   int i;
   for (i = 0; i < 30; i++) {
      unregister_kprobe(&(probes[i]));
   }

   printk(KERN_INFO MODULE_NAME "Cleaning up.\n");

   remove_proc_entry(uid_name, NULL);
   printk(KERN_INFO "/proc/%s removed\n", uid_name);
   remove_proc_entry(toggle_name, NULL);
   printk(KERN_INFO "/proc/%s removed\n", toggle_name);
   remove_proc_entry(log_name, NULL);
   printk(KERN_INFO "/proc/%s removed\n", log_name);

   printk(KERN_INFO MODULE_NAME "Done cleaning up.\n");
}
