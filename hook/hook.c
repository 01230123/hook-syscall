#include <asm/unistd.h>
#include <asm/cacheflush.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/pgtable_types.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <linux/fdtable.h>
MODULE_LICENSE("GPL");
/*MY sys_call_table address*/

void **system_call_table_addr;
/*my custom syscall that takes process name*/
asmlinkage long (*open) (const char*, int, umode_t);
asmlinkage long (*write) (unsigned int, const char*, size_t);
///*hook*/


asmlinkage long hook_open(const char* filename, int flags, umode_t mode)
{
 	char buff[200];
 	copy_from_user(buff, filename, 200);

	if(strcmp(current->comm,"test") == 0){
 	printk(KERN_INFO "file: %s is opened | hooked open file: %s\n", current->comm , buff);
	}

 	return open(filename, flags, mode);
}

asmlinkage int hook_write (unsigned int fd, const char* buf, int count) {
    char* tmp = kmalloc(256, GFP_KERNEL);
    char* fileName = d_path(&files_fdtable(current->files)->fd[fd]->f_path, tmp, 256);
    int bytes = (*write)(fd, buf, len);
	printk(KERN_INFO "hook found process %s has written %d bytes to %s\n", current->comm, bytes, fileName);
    kfree(tmp);
    return bytes;
}

/*Make page writeable*/
int make_rw(unsigned long address){
 	unsigned int level;
 	pte_t *pte = lookup_address(address, &level);
 	if(pte->pte &~_PAGE_RW){
 		pte->pte |=_PAGE_RW;
 	}
 	return 0;
}

/* Make the page write protected */
int make_ro(unsigned long address){
 	unsigned int level;
 	pte_t *pte = lookup_address(address, &level);
 	pte->pte = pte->pte & ~_PAGE_RW;
 	return 0;
}

static int __init entry_point(void){
 	printk(KERN_INFO "Hook loaded successfully!\n");
 	
 	system_call_table_addr = (void*)0xffffffff81e00280;
 	
	open = system_call_table_addr[__NR_open];
 	write = system_call_table_addr[__NR_write];

 	/*Disable page protection*/
 	make_rw((unsigned long)system_call_table_addr);

	/*Change syscall to our syscall function*/
 	system_call_table_addr[__NR_open] = hook_open;
	system_call_table_addr[__NR_write] = hook_write;
 	return 0;
}

static int __exit exit_point(void){
	 printk(KERN_INFO "Unloaded Hook successfully\n");
 
	 system_call_table_addr[__NR_open] = open;
	 system_call_table_addr[__NR_write] = write;
 	
	 /*Renable page protection*/
	 make_ro((unsigned long)system_call_table_addr);
 return 0;
}

module_init(entry_point);
module_exit(exit_point);

