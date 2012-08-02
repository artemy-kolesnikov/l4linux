/**
 * crypt_driver.c: Linux kernel proxy code
 *
 * (c) 2012 Artemy Kolesnikov <artemy.kolesnikov@gmail.com>
 */

#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <l4/re/c/util/cap_alloc.h>
#include <l4/re/c/dataspace.h>
#include <l4/re/c/mem_alloc.h>
#include <l4/re/c/rm.h>
#include <l4/re/env.h>
#include <l4/sys/ipc.h>
#include <l4/sys/vcon.h>

#define AUTHOR "Artemy Kolesnikov <artemy.kolesnikov@gmail.com>"
#define DESC "L4 IPC client code"
#define DEVICE_NAME "crypt"
#define MAX_DATA_SIZE 4096

#define CRYPT_CAP_NAME "crypt_server"

#define IOCTL_MAGIC '^'
#define IOCTL_ENCRYPT _IO(IOCTL_MAGIC, 1)
#define IOCTL_DECRYPT _IO(IOCTL_MAGIC, 2)

#define ROUND_W(X) ((X + (sizeof(int) - 1)) / sizeof(int))

struct user_data {
    char* inputBuffer;
    char* outputBuffer;
    size_t size;
};

enum crypt_server_operation {
    ENCRYPT_OP = 0,
    DECRYPT_OP = 1,
    GET_DS_OP = 2
};

static int init_crypt_module(void);
static void exit_crypt_module(void);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
static int device_open(struct inode*, struct file*);
static int device_release(struct inode*, struct file*);
static long device_ioctl(struct file*, unsigned int, unsigned long);
static int invoke_crypt_server_op(struct user_data* data, enum crypt_server_operation operation);

static int majorNumber;

static struct file_operations fops = {
    .owner = THIS_MODULE,
	.read = device_read,
	.write = device_write,
    .open = device_open,
    .release = device_release,
    .unlocked_ioctl = device_ioctl
};

static int __init init_crypt_module(void) {
	printk(KERN_INFO "Load crypt module\n");

    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);

	if (majorNumber < 0) {
        printk(KERN_ALERT "Registering crypt char device failed with %d\n", majorNumber);
        return -EFAULT;
	}

	return 0;
}

static void __exit exit_crypt_module(void) {
    unregister_chrdev(majorNumber, DEVICE_NAME);

	printk(KERN_INFO "Exit crypt module\n");
}

static ssize_t device_read(struct file* filp, char* buffer, size_t size, loff_t* offset) {
    struct user_data* data = filp->private_data;

    if (NULL == data->outputBuffer) {
        return -EFAULT;
    }

    if (copy_to_user(buffer, data->outputBuffer, data->size)) {
        return -EFAULT;
    }

    return 0;
}

static ssize_t device_write(struct file* filp, const char* buffer, size_t size, loff_t* offset) {
    struct user_data* data = filp->private_data;

    data->size = size > MAX_DATA_SIZE ? MAX_DATA_SIZE : size;

    if (NULL != data->inputBuffer) {
        kfree(data->inputBuffer);
        data->inputBuffer = NULL;
    }

    data->inputBuffer = (char*)kmalloc(data->size, GFP_KERNEL);
    if (data->inputBuffer == NULL) {
        printk(KERN_ERR "Cannot allocate memory size %d for user input", size);
        return -EFAULT;
    }

    if (copy_from_user(data->inputBuffer, buffer, data->size)) {
        return -EFAULT;
    }

    return data->size;
}

static int device_open(struct inode* inode, struct file* filp) {
    struct user_data* data = (struct user_data*)kmalloc(sizeof(struct user_data), GFP_KERNEL);
    if (NULL == data) {
        printk(KERN_ERR "Cannot allocate memory for user data");
        return -EFAULT;
    }

    memset(data, 0, sizeof(struct user_data));

    filp->private_data = data;

    return 0;
}

static int device_release(struct inode* inode, struct file* filp) {
    struct user_data* data = filp->private_data;
    kfree(data->inputBuffer);
    kfree(data->outputBuffer);
    kfree(data);

    return 0;
}

static long device_ioctl(struct file* filp, unsigned int cmd, unsigned long arg) {
    int result = -ENOTTY;

    struct user_data* data = filp->private_data;

    switch (cmd) {
        case IOCTL_ENCRYPT:
            result = invoke_crypt_server_op(data, ENCRYPT_OP);
            break;
        case IOCTL_DECRYPT:
            result = invoke_crypt_server_op(data, DECRYPT_OP);
            break;
    }

    return result;
}

static int invoke_crypt_server_op(struct user_data* data, enum crypt_server_operation operation) {
    l4_buf_regs_t* br = NULL;
    l4_cap_idx_t ds;
    l4_cap_idx_t server;
    l4_msg_regs_t* mr = NULL;
    l4_msgtag_t ret;
    l4_msgtag_t tag;
    l4re_ds_stats_t dsStats;
    long err = 0;
    unsigned long dsSize = 0;
    void* addr = NULL;

    server = l4re_get_env_cap(CRYPT_CAP_NAME);
    if (l4_is_invalid_cap(server)) {
        printk(KERN_ERR "Cannot get server capability");
        return -EFAULT;
    }

    ds = l4re_util_cap_alloc();
    if (!l4_is_valid_cap(ds)) {
        printk(KERN_ERR "Cannot allocate dataspace capability");

        l4re_util_cap_free(server);

        return -EFAULT;
    }

    br = l4_utcb_br_u(l4_utcb());
    br->bdr &= ~L4_BDR_OFFSET_MASK;
    br->br[0] = ds | L4_RCV_ITEM_SINGLE_CAP;

    tag = l4_msgtag(GET_DS_OP, 0, 0, 0);

    ret = l4_ipc_call(server, l4_utcb(), tag, L4_IPC_NEVER);

    if (l4re_ds_info(ds, &dsStats) != 0) {
        printk(KERN_ERR "Cannot get dataspace status");

        l4re_util_cap_free(server);
        l4re_util_cap_free(ds);

        return -EFAULT;
    }

    dsSize = dsStats.size;

    if (dsSize < data->size) {
        printk("Data size %d must be less or equal %d\n", data->size, dsSize);

        l4re_util_cap_free(ds);
        l4re_util_cap_free(server);

        return -EFAULT;
    }

    err = l4re_rm_attach(&addr, data->size, L4RE_RM_SEARCH_ADDR, ds, 0, 0);
    if (err < 0) {
        printk("Error attaching data space: %s\n", l4sys_errtostr(err));

        l4re_util_cap_free(ds);
        l4re_util_cap_free(server);

        return -EFAULT;
    }

    memcpy(addr, data->inputBuffer, data->size);

    mr = l4_utcb_mr();
    mr->mr[0] = data->size;

    tag = l4_msgtag(operation, 1, 0, 0);

    ret = l4_ipc_call(server, l4_utcb(), tag, L4_IPC_NEVER);

    if (l4_msgtag_has_error(ret)) {
        printk(KERN_ERR "Error during ipc send");

        l4re_rm_detach(addr);
        l4re_util_cap_free(ds);
        l4re_util_cap_free(server);

        return -EFAULT;
    }

    kfree(data->outputBuffer);
    data->outputBuffer = (char*)kmalloc(data->size, GFP_KERNEL);

    memcpy(data->outputBuffer, addr, data->size);

    l4re_rm_detach(addr);
    l4re_util_cap_free(ds);
    l4re_util_cap_free(server);

    return 0;
}

module_init(init_crypt_module);
module_exit(exit_crypt_module);

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_LICENSE("LGPL");
