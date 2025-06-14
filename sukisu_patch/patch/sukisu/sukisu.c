#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <asm/current.h>
#include <../include/accctl.h>
#include <ktypes.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm-generic/compat.h>
#include <uapi/asm-generic/errno.h>
#include <syscall.h>
#include <symbol.h>
#include <kconfig.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <taskob.h>
#include <predata.h>
#include <accctl.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <syscall.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <predata.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/umh.h>
#include <uapi/scdefs.h>
#include <uapi/linux/stat.h>
#include <uapi/asm-generic/unistd.h>
#include <ktypes.h>
#include <uapi/scdefs.h>
#include <hook.h>
#include <common.h>
#include <log.h>
#include <predata.h>
#include <pgtable.h>
#include <linux/syscall.h>
#include <uapi/asm-generic/errno.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <syscall.h>
#include <accctl.h>
#include <module.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <kputils.h>
#include <pidmem.h>
#include <predata.h>
#include <linux/random.h>
#include <sucompat.h>
#include <accctl.h>
#include <kstorage.h>

static long call_buildtime(char __user *out_buildtime, int u_len)
{
    const char *buildtime = get_build_time();
    int len = strlen(buildtime);
    if (len >= u_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_buildtime, buildtime, len + 1);
    return rc;
}

static long call_kpm_control(const char __user *arg1, const char *__user arg2, void *__user out_msg, int outlen)
{
    char name[KPM_NAME_LEN], args[KPM_ARGS_LEN];
    long namelen = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (namelen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return module_control0(name, arglen <= 0 ? 0 : args, out_msg, outlen);
}

static long call_kpm_unload(const char *__user arg1, void *__user reserved)
{
    char name[KPM_NAME_LEN];
    long len = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (len <= 0) return -EINVAL;
    return unload_module(name, reserved);
}

static long call_kpm_nums()
{
    return get_module_nums();
}

static long call_kpm_list(char *__user names, int len)
{
    if (len <= 0) return -EINVAL;
    char buf[4096];
    int sz = list_modules(buf, sizeof(buf));
    if (sz > len) return -ENOBUFS;
    sz = compat_copy_to_user(names, buf, len);
    return sz;
}

static long call_kpm_info(const char *__user uname, char *__user out_info, int out_len)
{
    if (out_len <= 0) return -EINVAL;
    char name[64];
    char buf[2048];
    int len = compat_strncpy_from_user(name, uname, sizeof(name));
    if (len <= 0) return -EINVAL;
    int sz = get_module_info(name, buf, sizeof(buf));
    if (sz < 0) return sz;
    if (sz > out_len) return -ENOBUFS;
    sz = compat_copy_to_user(out_info, buf, sz);
    return sz;
}

// =====================================================================================

void before_sukisu_load_module_path(hook_fargs4_t* args, void* udata) {
    const char* path = (const char*) args->arg0;
    const char* arg = (const char*) args->arg1;
    void* ptr = (void*) args->arg2;
    void __user* result = (void*) args->arg3;

    logkfi("Load KPM: %s", path);

    int res = (int) load_module_path(path, arg, ptr);
    compat_copy_to_user(result, &res, sizeof(res));
    args->skip_origin = 1;
}

void before_sukisu_unload_module(hook_fargs3_t* args,void* udata) {
    const char* name = (const char*)args->arg0;
    void* ptr = (void*) args->arg1;
    void __user* result = (void*) args->arg2;
    int res = (int) unload_module(name, ptr);

    compat_copy_to_user(result, &res, sizeof(res));
    args->skip_origin = 1;
}

void before_sukisu_kpm_num(hook_fargs1_t* args, void* udata) {
    void __user* result = (void*) args->arg0;

    int res = (int) get_module_nums();
    compat_copy_to_user(result, &res, sizeof(res));
    args->skip_origin = 1;
}

void before_sukisu_kpm_list(hook_fargs3_t* args, void* udata) {
    char* __user out = (char* __user) args->arg0;
    int len = (int) args->arg1;
    void __user* result = (void*) args->arg2;

    int res = (int) call_kpm_list(out, len);
    
    compat_copy_to_user(result, &res, sizeof(res));
    args->skip_origin = 1;
}

void before_sukisu_kpm_info(hook_fargs3_t* args, void* udata) {
    char* name = (char*) args->arg0;
    char* __user out = (char* __user) args->arg1;
    void __user* result = (void*) args->arg2;
    char buf[256];
    int sz = get_module_info(name, buf, sizeof(buf));

    sz = compat_copy_to_user(out, buf, sz);
    int res = (int) sz;

    compat_copy_to_user(result, &res, sizeof(res));
    args->skip_origin = 1;
}

void before_sukisu_kpm_version(hook_fargs3_t* args, void* udata) {
    char __user* out = (char __user*) args->arg0;
    unsigned int outlen = (unsigned int) args->arg1;
    void __user* result = (void*) args->arg2;
    char buffer[256] = {0};

    const char *buildtime = get_build_time();

    snprintf(buffer, sizeof(buffer)-1, "%d (%s)", kpver, buildtime);

    int len = strlen(buffer);
    if (len >= outlen) len = outlen - 1;
    int rc = compat_copy_to_user(out, buffer, len + 1);
    int res = (int) rc;

    compat_copy_to_user(result, &res, sizeof(res));
    args->skip_origin = 1;
}


void before_sukisu_kpm_control(hook_fargs3_t* args, void* udata) {
    char __user* name = (char __user*) args->arg0;
    char __user* arg = (char __user*) args->arg1;
    void __user* result = (void*) args->arg2;
    int res = (int) call_kpm_control(name, arg, NULL, 0);

    compat_copy_to_user(result, &res, sizeof(res));
    args->skip_origin = 1;
}

void init_sukisu_ultra() {
    unsigned long addr;
    int rc;

    addr = kallsyms_lookup_name("sukisu_kpm_load_module_path");
    if(addr) {
        rc = hook_wrap4((void*) addr, before_sukisu_load_module_path, NULL, NULL);
        log_boot("hook sukisu_load_module_path rc:%d \n", rc);
    } else {
        log_boot("hook sukisu_load_module_path faild \n", rc);
    }

    addr = kallsyms_lookup_name("sukisu_kpm_unload_module");
    if(addr) {
        rc = hook_wrap3((void*) addr, before_sukisu_unload_module, NULL, NULL);
        log_boot("hook sukisu_kpm_unload_module rc:%d \n", rc);
    } else {
        log_boot("hook sukisu_kpm_unload_module faild \n", rc);
    }

    addr = kallsyms_lookup_name("sukisu_kpm_num");
    if(addr) {
        rc = hook_wrap1((void*) addr, before_sukisu_kpm_num, NULL, NULL);
        log_boot("hook sukisu_kpm_num rc:%d \n", rc);
    } else {
        log_boot("hook sukisu_kpm_num faild \n", rc);
    }

    addr = kallsyms_lookup_name("sukisu_kpm_list");
    if(addr) {
        rc = hook_wrap3((void*) addr, before_sukisu_kpm_list, NULL, NULL);
        log_boot("hook sukisu_kpm_list rc:%d \n", rc);
    } else {
        log_boot("hook sukisu_kpm_list faild \n", rc);
    }

    addr = kallsyms_lookup_name("sukisu_kpm_info");
    if(addr) {
        rc = hook_wrap3((void*) addr, before_sukisu_kpm_info, NULL, NULL);
        log_boot("hook sukisu_kpm_info rc:%d \n", rc);
    } else {
        log_boot("hook sukisu_kpm_info faild \n", rc);
    }

    addr = kallsyms_lookup_name("sukisu_kpm_control");
    if(addr) {
        rc = hook_wrap3((void*) addr, before_sukisu_kpm_control, NULL, NULL);
        log_boot("hook sukisu_kpm_control rc:%d \n", rc);
    } else {
        log_boot("hook sukisu_kpm_control faild \n", rc);
    }

    addr = kallsyms_lookup_name("sukisu_kpm_version");
    if(addr) {
        rc = hook_wrap3((void*) addr, before_sukisu_kpm_version, NULL, NULL);
        log_boot("hook sukisu_kpm_version rc:%d \n", rc);
    } else {
        log_boot("hook sukisu_kpm_version faild \n", rc);
    }

}