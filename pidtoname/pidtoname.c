#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/string.h>
#include "pidtoname.h"

asmlinkage long sys_pidtoname(int pid, char* buf, int len) {
	printk("DEBUG: %s - %d\n", buf, len);
	len = len - 1;
	struct task_struct *task;
	int result = -1;
	for_each_process(task){
		if(task->pid == pid) {
			int pidname_len = strlen(task->comm);
			if (pidname_len <= len)
			{
				strcpy(buf, task->comm);
				result = 0;
			}
			else
			{
				strncpy(buf, task->comm, len);
				result = pidname_len;
			}
		}
	}
	printk("DEBUG RESULT: %d\n", result);
	return (long)result;
}
