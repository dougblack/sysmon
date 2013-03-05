
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <asm/current.h>
#include <asm/uaccess.h>

#define uid_name "sysmon_uid"
#define toggle_name "sysmon_toggle"
#define log_name "sysmon_log"

struct proc_dir_entry *uid_entry;
struct proc_dir_entry *toggle_entry;
struct proc_dir_entry *log_entry;

int uid_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
   int ret;
   if (offset > 0) {
      ret = 0; 
   } else {
      /* RETURN UID VALUE HERE */
   }
}
int uid_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
}
int toggle_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{

   int ret;
   if (offset > 0) {
      ret = 0; 
   } else {
      /* RETURN TOGGLE VALUE HERE */
   }
}
int toggle_write(struct file *file, const char *buffer, unsigned long count, void *data)
{

}
int log_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
   int ret;
   if (offset > 0) {
      ret = 0; 
   } else {
      /* RETURN LOG HERE */
   }
}

int init_module()
{
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
