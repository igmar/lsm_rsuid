/*
 * (c) 2005 Igmar Palsenberg (igmar@palsenberg.com)
 *
 * set*uid() call relaxer for certain processes
 *
 * The free distribution and use of this software in both source and binary
 * form is allowed (with or without changes) provided that:
 * 
 * 1. distributions of this source code include the above copyright
 *    notice, this list of conditions and the following disclaimer;
 *
 * 2. distributions in binary form include the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in the documentation and/or other associated materials;
 * 
 * 3. the copyright holder's name is not used to endorse products
 *    built using this software without specific written permission.
 *
 *
 * DISCLAIMER
 *
 * This software is provided 'as is' with no explicit or implied warranties
 * in respect of its properties, including, but not limited to, correctness
 * and/or fitness for purpose.
 *    
*/

#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/sysctl.h>
#include <linux/highuid.h>
#include <linux/string.h>

#define LSM_RSUID_MAJOR		1
#define LSM_RSUID_MINOR		1

#define MY_NAME			"rsuid"
#define RSUID_ENABLE		"rsuid enable"
#define RSUID_DISABLE		"rsuid disable"

/* {{{ global statics */
/* Here we define minimum uid and gid values */
static int rsuid_enabled = 0;
static int rsuid_uid_min = -1;
static int rsuid_uid_max = DEFAULT_OVERFLOWUID;
static int rsuid_gid_min = -1;
static int rsuid_gid_max = DEFAULT_OVERFLOWGID;
/* }}} */

/* {{{ struct rsuid_struct */
struct rsuid_struct {
	int enabled;
	int curr_suid;
	pid_t pid;
};
/* }}} */

/* {{{ rsuid_proc_handle_enable */
static int rsuid_proc_handle_enable(ctl_table *table, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int res = 0;

	res = proc_dointvec(table, write, filp, buffer, lenp, ppos);
	if (res)
		return res;

	if (rsuid_enabled) {
		if (rsuid_uid_min == -1 || rsuid_uid_max == -1) {
			printk(KERN_WARNING "process '%d' tried to enable rsuid LSM when uid_min or uid_max aren't set\n", current->pid);
			rsuid_enabled = 0;
			return -EACCES;
		}
		if (rsuid_uid_min == 0 || rsuid_uid_max == 0) {
			printk(KERN_WARNING "process '%d' tried to enable rsuid LSM when uid_min or uid_max are set to 0\n", current->pid);
			rsuid_enabled = 0;
			return -EACCES;
		}
		if (rsuid_gid_min == -1 || rsuid_gid_max == -1) {
			printk(KERN_WARNING "process '%d' tried to enable rsuid LSM when gid_min or gid_max aren't set\n", current->pid);
			rsuid_enabled = 0;
			return -EACCES;
		}
		if (rsuid_gid_min == 0 || rsuid_gid_max == 0) {
			printk(KERN_WARNING "process '%d' tried to enable rsuid LSM when gid_min or gid_max are set to 0\n", current->pid);
			rsuid_enabled = 0;
			return -EACCES;
		}
	}

	return 0;
}
/* }}} */

/* {{{ rsuid_proc_handle_uid_max */
static int rsuid_proc_handle_uid_max(ctl_table *table, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int res = 0;
	int cur_max_uid = rsuid_uid_max;

	res = proc_dointvec(table, write, filp, buffer, lenp, ppos);
	if (res)
		return res;

	if (rsuid_enabled && write) {
		rsuid_uid_max = cur_max_uid;
		res = -EACCES;
	}

	return res;
}
/* }}} */

/* {{{ rsuid_proc_handle_uid_min */
static int rsuid_proc_handle_uid_min(ctl_table *table, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int res = 0;
	int cur_min_uid = rsuid_uid_min;

	res = proc_dointvec(table, write, filp, buffer, lenp, ppos);
	if (res)
		return res;

	if (rsuid_enabled && write) {
		rsuid_uid_min = cur_min_uid;
		res = -EACCES;
	}

	return res;
}
/* }}} */

/* {{{ rsuid_proc_handle_gid_max */
static int rsuid_proc_handle_gid_max(ctl_table *table, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int res = 0;
	int cur_gid_max = rsuid_gid_max;

	res = proc_dointvec(table, write, filp, buffer, lenp, ppos);
	if (res)
		return res;

	if (rsuid_enabled && write) {
		rsuid_gid_max = cur_gid_max;
		res = -EACCES;
	}

	return res;
}
/* }}} */

/* {{{ rsuid_proc_handle_gid_min */
static int rsuid_proc_handle_gid_min(ctl_table *table, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int res = 0;
	int cur_gid_min = rsuid_gid_min;

	res = proc_dointvec(table, write, filp, buffer, lenp, ppos);
	if (res)
		return res;

	if (rsuid_enabled && write) {
		rsuid_gid_min = cur_gid_min;
		res = -EACCES;
	}

	return res;
}
/* }}} */

/* {{{ sysctl entry structs */
#define SYSCTL_RSUID		98
#define RSUID_ENABLED		1
#define RSUID_UID_MIN		2
#define RSUID_UID_MAX		3
#define RSUID_GID_MIN		2
#define RSUID_GID_MAX		3

static ctl_table rsuid_table[] = {
	{
		.ctl_name 	= RSUID_UID_MIN,
		.procname	= "uid_min",
		.data 		= &rsuid_uid_min,
		.maxlen		= sizeof(int),
		.mode		= 0640,
		.proc_handler	= &rsuid_proc_handle_uid_min
	},
	{
		.ctl_name	= RSUID_UID_MAX,
		.procname	= "uid_max",
		.data		= &rsuid_uid_max,
		.maxlen 	= sizeof(int),
		.mode		= 0640,
		.proc_handler	= &rsuid_proc_handle_uid_max
	},
	{
		.ctl_name 	= RSUID_GID_MIN,
		.procname	= "gid_min",
		.data 		= &rsuid_gid_min,
		.maxlen		= sizeof(int),
		.mode		= 0640,
		.proc_handler	= &rsuid_proc_handle_gid_min
	},
	{
		.ctl_name	= RSUID_GID_MAX,
		.procname	= "gid_max",
		.data		= &rsuid_gid_max,
		.maxlen 	= sizeof(int),
		.mode		= 0640,
		.proc_handler	= &rsuid_proc_handle_gid_max
	},
	{
		.ctl_name	= RSUID_ENABLED,
		.procname	= "enabled",
		.data		= &rsuid_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0640,
		.proc_handler	= &rsuid_proc_handle_enable
	}

};

static ctl_table rsuid_dir_table[] = {
	{
		.ctl_name = SYSCTL_RSUID,
		.procname = "rsuid",
		.maxlen = 0,
		.mode = 0555,
		.child = rsuid_table,
	},
	{ .ctl_name = 0 }
};

static ctl_table rsuid_root_table[] = {
	{
		.ctl_name = CTL_KERN,
		.procname = "kernel",
		.maxlen = 0,
		.mode = 0555,
		.child = rsuid_dir_table,
	},
	{ .ctl_name = 0 }
};

static struct ctl_table_header *sysctl_root_table = NULL;
/* }}} */

/* {{{ LSM hooks prototypes */
static int rsuid_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags);
static int rsuid_task_post_setuid(uid_t id0, uid_t id1, uid_t id2, int flags);
static int rsuid_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags);
static int rsuid_task_setgroups(struct group_info *group_info);
static int rsuid_task_alloc_security(struct task_struct *task);
static void rsuid_task_free_security(struct task_struct *task);
static int rsuid_setprocattr(struct task_struct *task, char *name, void *value, size_t size);
static int rsuid_getprocattr(struct task_struct *task, char *name, void *value, size_t size);
/* }}} */

/* Operations we handle */
/* {{{ rsuid_security_ops */
static struct security_operations rsuid_security_ops = {
	.task_setuid = 			rsuid_task_setuid,
	.task_post_setuid = 		rsuid_task_post_setuid,
	.task_setgid = 			rsuid_task_setgid,
	.task_setgroups = 		rsuid_task_setgroups,
	.task_alloc_security = 		rsuid_task_alloc_security,
	.task_free_security = 		rsuid_task_free_security,
	.setprocattr =			rsuid_setprocattr,
	.getprocattr = 			rsuid_getprocattr,
};
/* }}} */

/* {{{ static int rsuid_register_security(void) */
static int rsuid_register_security(void)
{
	if (register_security(&rsuid_security_ops)) {
		printk (KERN_INFO "Failure registering mod_suid LSM.\n");
		return -EINVAL;
	}
	return 0;
}
/* }}} */

/* {{{ static void rsuid_unregister_security(void) */
static void rsuid_unregister_security(void)
{
	if (unregister_security (&rsuid_security_ops))
		printk (KERN_INFO "Failure unregistering mod_suid LSM module with the kernel\n");
}
/* }}} */

/* {{{ static int __init rsuid_init(void) */
static int __init rsuid_init(void)
{
	int err;

	err = rsuid_register_security();
	if (err)
		return err;

	sysctl_root_table = register_sysctl_table(rsuid_root_table, 0);
	if (!sysctl_root_table) {
		printk(KERN_WARNING "sysctl registration failed, aborting LSM initialization\n");
		rsuid_unregister_security();
		return -ENOMEM;
	}
	printk (KERN_INFO "rsuid LSM version %d.%d initialized\n", LSM_RSUID_MAJOR, LSM_RSUID_MINOR);

	return 0;
}
/* }}} */

/* {{{ static void __exit rsuid_exit(void) */
static void __exit rsuid_exit(void)
{
	rsuid_unregister_security();
	unregister_sysctl_table(sysctl_root_table);
	sysctl_root_table = NULL;

	printk (KERN_INFO "rsuid LSM removed\n");
}
/* }}} */

/* The LSM hooks */
/* {{{ lsm_task_setuid */
static int rsuid_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
	struct rsuid_struct *tsec = current->security;

	if (!rsuid_enabled || !tsec || tsec->enabled == 0)
		return 0;
	
	BUG_ON(tsec->pid != current->pid);
	
	switch (flags) {
		case LSM_SETID_ID:
			/* suid == id0 */
			if (id0 == -1)
				return -EPERM;
			if (id0 < rsuid_uid_min || id0 > rsuid_uid_max)
				return -EACCES;
			tsec->curr_suid = id0;
			break;
		case LSM_SETID_RE:
			/* suid == id1, so if id1 == -1, return an error */
			if (id0 == -1 || id1 == -1)
				return -EPERM;
			if (id0 != id1)
				return -EPERM;
			if (id0 < rsuid_uid_min || id0 > rsuid_uid_max)
				return -EACCES;
			if (id1 < rsuid_uid_min || id1 > rsuid_uid_max)
				return -EACCES;
			tsec->curr_suid = id1;
			break;
		case LSM_SETID_RES:
			if (id0 == -1 || id1 == -1 || id2 == -1)
				return -EPERM;
			if (id0 != id1 && id1 != id2)
				return -EPERM;
			if (id0 < rsuid_uid_min || id0 > rsuid_uid_max)
				return -EACCES;
			if (id1 < rsuid_uid_min || id1 > rsuid_uid_max)
				return -EACCES;
			if (id2 < rsuid_uid_min || id2 > rsuid_uid_max)
				return -EACCES;
			tsec->curr_suid = id2;
			break;
		case LSM_SETID_FS:
			if (id0 == -1)
				return -EPERM;
			if (id0 < rsuid_uid_min || id0 > rsuid_uid_max)
				return -EACCES;
			break;
		default:
			return -EINVAL;
			break;
	}
	/* Ok.. set suid to 0 */
	current->suid = 0;
	cap_raise(current->cap_effective, CAP_SETUID);

	return 0;
}
/* }}} */

/* {{{ static void handle_dummy_caps(struct task_struct *target) */
static void handle_dummy_caps(struct task_struct *target)
{
	target->cap_effective = target->cap_inheritable, target->cap_permitted = 0;
	if (!issecure(SECURE_NOROOT)) {
		if (target->euid == 0) {
			target->cap_permitted |= (~0 & ~CAP_FS_MASK);
			target->cap_effective |= (~0 & ~CAP_TO_MASK(CAP_SETPCAP) & ~CAP_FS_MASK);
		}
		if (target->fsuid == 0) {
			target->cap_permitted |= CAP_FS_MASK;
			target->cap_effective |= CAP_FS_MASK;
		}
	}
}
/* }}} */

/* {{{ lsm_task_post_setuid */
static int rsuid_task_post_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
	struct rsuid_struct *tsec = current->security;

	if (!rsuid_enabled || !tsec || tsec->enabled == 0) {
		handle_dummy_caps(current);
		return 0;
	}

	BUG_ON(tsec->pid != current->pid);
	current->suid = tsec->curr_suid;
	cap_lower(current->cap_effective, CAP_SETUID);

	return 0;
}
/* }}} */

/* {{{ rsuid_task_setgid */
static int rsuid_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags)
{
	struct rsuid_struct *tsec = current->security;

	if (!rsuid_enabled || !tsec || tsec->enabled == 0)
		return 0;

	BUG_ON(tsec->pid != current->pid);

	switch (flags) {
		case LSM_SETID_ID:
			if (id0 == -1)
				return -EPERM;
			if (id0 < rsuid_gid_min || id0 > rsuid_gid_max)
				return -EACCES;
			break;
		case LSM_SETID_RE:
			if (id0 == -1 || id1 == -1)
				return -EPERM;
			if (id0 != id1)
				return -EPERM;
			if (id0 < rsuid_gid_min || id0 > rsuid_gid_max)
				return -EACCES;
			if (id1 < rsuid_gid_min || id1 > rsuid_gid_max)
				return -EACCES;
			break;
		case LSM_SETID_RES:
			if (id0 == -1 || id1 == -1 || id2 == -1)
				return -EPERM;
			if (id0 != id1 && id1 != id2)
				return -EPERM;
			if (id0 < rsuid_gid_min || id0 > rsuid_gid_max)
				return -EACCES;
			if (id1 < rsuid_gid_min || id1 > rsuid_gid_max)
				return -EACCES;
			if (id2 < rsuid_gid_min || id2 > rsuid_gid_max)
				return -EACCES;
			break;
		case LSM_SETID_FS:
			if (id0 == -1)
				return -EPERM;
			if (id0 < rsuid_gid_min || id0 > rsuid_gid_max)
				return -EACCES;
			break;
	}
	return 0;
}
/* }}} */

/* {{{ rsuid_task_setgroups */
static int rsuid_task_setgroups(struct group_info *group_info)
{
	struct rsuid_struct *tsec = current->security;
	int i;

	if (!rsuid_enabled || !tsec || tsec->enabled == 0)
		return 0;

	BUG_ON(tsec->pid != current->pid);

	/* FIXME : do we need to handle indirect blocks ?? */
	for (i = 0; i < group_info->ngroups; i++) {
		if (group_info->small_block[i] < rsuid_gid_min || group_info->small_block[i] > rsuid_gid_max)
			return -EACCES;
	}

	return 0;
}
/* }}} */

/* {{{ static struct rsuid_struct * alloc_task_security(struct task_struct *task) */
static struct rsuid_struct * alloc_task_security(struct task_struct *task, struct task_struct *parent)
{
	struct rsuid_struct *tsec, *psec;
      
	tsec = kmalloc(sizeof(struct rsuid_struct), GFP_KERNEL);
	if (!tsec)
		return ERR_PTR(-ENOMEM);

	tsec->pid = task->pid;
	tsec->enabled = 0;
	tsec->curr_suid = 0;

	if (parent && parent->security) {
		psec = parent->security;
		tsec->enabled = psec->enabled;
	}

	return tsec;
}
/* }}} */

/* {{{ static void free_task_security(struct task_struct *task) */
static void free_task_security(struct task_struct *task)
{
	struct rsuid_struct *tsec = task->security;

	kfree(tsec);
	task->security = NULL;
}
/* }}} */

/* {{{ rsuid_task_alloc_security */
static int rsuid_task_alloc_security(struct task_struct *task)
{
	/* Parent doesn't have a security object. */
	if (!current->security)
		return 0;

	task->security = alloc_task_security(task, current);
	if (IS_ERR(task->security)) {
		task->security = NULL;
		return -ENOMEM;
	}

	return 0;
}
/* }}} */

/* {{{ rsuid_task_free_security */
static void rsuid_task_free_security(struct task_struct *task)
{
	if (!task->security)
		return;
	free_task_security(task);
}
/* }}} */

/*
 * LSM /proc/<pid>/attr hooks
 * You may write into /proc/<pid>/attr/exec :
 * rsuid enable
*/
/* {{{ rsuid_setprocattr */
static int rsuid_setprocattr(struct task_struct *task, char *name, void *value, size_t size)
{
	struct rsuid_struct *tsec = task->security;

	if (!rsuid_enabled)
		return -EPERM;

	if (task != current)
		return -EACCES;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (!tsec) {
		tsec = alloc_task_security(task, NULL);
		if (IS_ERR(tsec))
			return -ENOMEM;
		task->security = tsec;
	}

	/* Not writing into exec, return EPERM */
	if (strcmp(name, "exec"))
		return -EPERM;

	if (strncmp(value, RSUID_ENABLE, size) == 0) {
		if (tsec->enabled == 0) {
			/* Wipe all capabilities */
			cap_clear(current->cap_permitted);
			cap_clear(current->cap_effective);
			cap_raise(task->cap_effective, CAP_SETGID);
			cap_raise(task->cap_effective, CAP_SETUID);
			tsec->enabled = 1;
		} else
			return -EINVAL;
	} else
		return -EINVAL;
	
	return size; 
}
/* }}} */

/* LSM /proc/<pid>/attr read hooks
 * cat proc/<pid>/attr/current will print if rsuid is enabled
 * cat /proc/<pid>/attr/exec output :
 * a restricted process will get -EINVAL
 * a non-restricted process will get a hint on setting the restriction
 * 
*/
/* {{{ rsuid_getprocattr */
static int rsuid_getprocattr(struct task_struct *task, char *name, void *value, size_t size)
{
	struct rsuid_struct *tsec = current->security;
	int err = -EINVAL;
	
	if (!rsuid_enabled)
		return -EPERM;

	if (strcmp(name, "current") == 0) {
		if (tsec && tsec->enabled)
			err = snprintf(value, size, "RSUID enabled\n");
		else
			err = snprintf(value, size, "RSUID disabled\n");
	} else if (strcmp(name, "exec") == 0) {
		if (!tsec || !tsec->enabled)
			err = snprintf(value, size, 
					"Valid keywords:\n"
					"rsuid [enable|disable]\n");
	} else
		err = -EINVAL;

	return err;
}
/* }}} */

security_initcall (rsuid_init);
module_exit (rsuid_exit);

MODULE_DESCRIPTION("LSM module to enable processes to switch to certain UID's");
MODULE_AUTHOR("Igmar Palsenberg <igmar@palsenberg.com>");
MODULE_LICENSE("Dual BSD/GPL");
