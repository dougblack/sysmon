
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <linux/kprobes.h>

#include <asm/current.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");

#define uid_name "sysmon_uid"
#define toggle_name "sysmon_toggle"
#define log_name "sysmon_log"

#define MAX_BUFFER_SIZE 1024

static char *probe_names[] = {"sys_access", "sys_brk", "sys_chdir", "sys_chmod", "sys_clone", "sys_close", "sys_dup", "sys_dup2", "sys_execve", "sys_exit_group", "sys_fcntl", "sys_fork", "sys_getdents", "sys_getpid", "sys_gettid", "sys_ioctl", "sys_lseek", "sys_mkdir", "sys_mmap", "sys_munmap", "sys_open", "sys_pipe", "sys_read", "sys_rmdir", "sys_select", "sys_stat", "sys_fstat", "sys_lstat", "sys_wait4", "sys_write"};

/* The KPROBE! */
static struct kprobe *probes[30];

struct proc_dir_entry *uid_entry;
struct proc_dir_entry *toggle_entry;
struct proc_dir_entry *log_entry;

int toggle = 0;
int uid = 0;

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
int log_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
   int ret_length;
   if (offset > 0) {
      ret_length = 0; 
   } else {
      /* ret_lengthURN LOG HERE */
   }
   return ret_length;
}

static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
   int ret = 0;
   if (current->uid != uid)
      return 0;
   switch (regs->rax) {
      case __NR_mkdir:
         printk(KERN_INFO "%lu %d %d args 0x%lu '%s' %d\n", regs->rax, current->pid, current->tgid, (uintptr_t) regs->rdi, (char *) regs->rdi, (int) regs->rsi);
         break;
      default:
         printk(KERN_INFO "sysmon intercept before.\n");
         ret = -1;
         break;
   }
   return ret;
}

static void sysmon_intercept_after(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
   /* Capture return code. */
}


int init_module()
{

   int i;
   struct kprobe *probe;

   for (i = 0; i < 30; i++) {
      probe = probes[i];
      probe->symbol_name = probe_names[i];
      probe->pre_handler = sysmon_intercept_before;
      probe->post_handler = sysmon_intercept_after;

      if (register_kprobe(probe)) {
         printk(KERN_ERR "register_kprobe failed.\n");
         return -EFAULT;
      }
   }   

   uid_entry = create_proc_entry(uid_name, 0600, NULL);
   toggle_entry = create_proc_entry(toggle_name, 0600, NULL);
   log_entry = create_proc_entry(log_name, 0600, NULL);
  
   if (uid_entry == NULL || toggle_entry == NULL || log_entry == NULL) {
      remove_proc_entry(uid_name, NULL);
      remove_proc_entry(toggle_name, NULL);
      remove_proc_entry(log_name, NULL);
   }

   uid_entry->read_proc = uid_read;
   uid_entry->write_proc = uid_write;
   uid_entry->owner = THIS_MODULE;

   toggle_entry->read_proc = toggle_read;
   toggle_entry->write_proc = toggle_write;
   toggle_entry->owner = THIS_MODULE;

   log_entry->read_proc = log_read;
   log_entry->owner = THIS_MODULE;
  
   return 0; 
}


void cleanup_module()
{
   remove_proc_entry(uid_name, NULL);
   printk(KERN_INFO "/proc/%s removed\n", uid_name);
   remove_proc_entry(toggle_name, NULL);
   printk(KERN_INFO "/proc/%s removed\n", toggle_name);
   remove_proc_entry(log_name, NULL);
   printk(KERN_INFO "/proc/%s removed\n", log_name);
}
