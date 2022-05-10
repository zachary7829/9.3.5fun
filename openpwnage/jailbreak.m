//
//  jailbreak.m
//  openpwnage
//
//  Created by Zachary Keffaber on 4/24/22.
//

//90% of this is stolen from spv

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <UIKit/UIKit.h>

#import "ViewController.h"

#define UNSLID_BASE 0x80001000

void flush_all_the_streams(void) {
    fflush(stdout);
    fflush(stderr);
}

void olog(char *format, ...) {
    flush_all_the_streams();
    char msg[1000];//this can overflow, but eh don't care
    va_list aptr;

    va_start(aptr, format);
    vsprintf(msg, format, aptr);
    va_end(aptr);
    printf("%s",msg);

    NSString *logTxt = [NSString stringWithUTF8String:msg];
    NSLog(@"%@",logTxt);
    openpwnageCLog(logTxt);
    flush_all_the_streams();
}

//from doubleh3lix

struct mac_policy_ops {
    uint32_t mpo_audit_check_postselect;
    uint32_t mpo_audit_check_preselect;
    uint32_t mpo_bpfdesc_label_associate;
    uint32_t mpo_bpfdesc_label_destroy;
    uint32_t mpo_bpfdesc_label_init;
    uint32_t mpo_bpfdesc_check_receive;
    uint32_t mpo_cred_check_label_update_execve;
    uint32_t mpo_cred_check_label_update;
    uint32_t mpo_cred_check_visible;
    uint32_t mpo_cred_label_associate_fork;
    uint32_t mpo_cred_label_associate_kernel;
    uint32_t mpo_cred_label_associate;
    uint32_t mpo_cred_label_associate_user;
    uint32_t mpo_cred_label_destroy;
    uint32_t mpo_cred_label_externalize_audit;
    uint32_t mpo_cred_label_externalize;
    uint32_t mpo_cred_label_init;
    uint32_t mpo_cred_label_internalize;
    uint32_t mpo_cred_label_update_execve;
    uint32_t mpo_cred_label_update;
    uint32_t mpo_devfs_label_associate_device;
    uint32_t mpo_devfs_label_associate_directory;
    uint32_t mpo_devfs_label_copy;
    uint32_t mpo_devfs_label_destroy;
    uint32_t mpo_devfs_label_init;
    uint32_t mpo_devfs_label_update;
    uint32_t mpo_file_check_change_offset;
    uint32_t mpo_file_check_create;
    uint32_t mpo_file_check_dup;
    uint32_t mpo_file_check_fcntl;
    uint32_t mpo_file_check_get_offset;
    uint32_t mpo_file_check_get;
    uint32_t mpo_file_check_inherit;
    uint32_t mpo_file_check_ioctl;
    uint32_t mpo_file_check_lock;
    uint32_t mpo_file_check_mmap_downgrade;
    uint32_t mpo_file_check_mmap;
    uint32_t mpo_file_check_receive;
    uint32_t mpo_file_check_set;
    uint32_t mpo_file_label_init;
    uint32_t mpo_file_label_destroy;
    uint32_t mpo_file_label_associate;
    uint32_t mpo_ifnet_check_label_update;
    uint32_t mpo_ifnet_check_transmit;
    uint32_t mpo_ifnet_label_associate;
    uint32_t mpo_ifnet_label_copy;
    uint32_t mpo_ifnet_label_destroy;
    uint32_t mpo_ifnet_label_externalize;
    uint32_t mpo_ifnet_label_init;
    uint32_t mpo_ifnet_label_internalize;
    uint32_t mpo_ifnet_label_update;
    uint32_t mpo_ifnet_label_recycle;
    uint32_t mpo_inpcb_check_deliver;
    uint32_t mpo_inpcb_label_associate;
    uint32_t mpo_inpcb_label_destroy;
    uint32_t mpo_inpcb_label_init;
    uint32_t mpo_inpcb_label_recycle;
    uint32_t mpo_inpcb_label_update;
    uint32_t mpo_iokit_check_device;
    uint32_t mpo_ipq_label_associate;
    uint32_t mpo_ipq_label_compare;
    uint32_t mpo_ipq_label_destroy;
    uint32_t mpo_ipq_label_init;
    uint32_t mpo_ipq_label_update;
    uint32_t mpo_file_check_library_validation;
    uint32_t mpo_vnode_notify_setacl;
    uint32_t mpo_vnode_notify_setattrlist;
    uint32_t mpo_vnode_notify_setextattr;
    uint32_t mpo_vnode_notify_setflags;
    uint32_t mpo_vnode_notify_setmode;
    uint32_t mpo_vnode_notify_setowner;
    uint32_t mpo_vnode_notify_setutimes;
    uint32_t mpo_vnode_notify_truncate;
    uint32_t mpo_mbuf_label_associate_bpfdesc;
    uint32_t mpo_mbuf_label_associate_ifnet;
    uint32_t mpo_mbuf_label_associate_inpcb;
    uint32_t mpo_mbuf_label_associate_ipq;
    uint32_t mpo_mbuf_label_associate_linklayer;
    uint32_t mpo_mbuf_label_associate_multicast_encap;
    uint32_t mpo_mbuf_label_associate_netlayer;
    uint32_t mpo_mbuf_label_associate_socket;
    uint32_t mpo_mbuf_label_copy;
    uint32_t mpo_mbuf_label_destroy;
    uint32_t mpo_mbuf_label_init;
    uint32_t mpo_mount_check_fsctl;
    uint32_t mpo_mount_check_getattr;
    uint32_t mpo_mount_check_label_update;
    uint32_t mpo_mount_check_mount;
    uint32_t mpo_mount_check_remount;
    uint32_t mpo_mount_check_setattr;
    uint32_t mpo_mount_check_stat;
    uint32_t mpo_mount_check_umount;
    uint32_t mpo_mount_label_associate;
    uint32_t mpo_mount_label_destroy;
    uint32_t mpo_mount_label_externalize;
    uint32_t mpo_mount_label_init;
    uint32_t mpo_mount_label_internalize;
    uint32_t mpo_netinet_fragment;
    uint32_t mpo_netinet_icmp_reply;
    uint32_t mpo_netinet_tcp_reply;
    uint32_t mpo_pipe_check_ioctl;
    uint32_t mpo_pipe_check_kqfilter;
    uint32_t mpo_pipe_check_label_update;
    uint32_t mpo_pipe_check_read;
    uint32_t mpo_pipe_check_select;
    uint32_t mpo_pipe_check_stat;
    uint32_t mpo_pipe_check_write;
    uint32_t mpo_pipe_label_associate;
    uint32_t mpo_pipe_label_copy;
    uint32_t mpo_pipe_label_destroy;
    uint32_t mpo_pipe_label_externalize;
    uint32_t mpo_pipe_label_init;
    uint32_t mpo_pipe_label_internalize;
    uint32_t mpo_pipe_label_update;
    uint32_t mpo_policy_destroy;
    uint32_t mpo_policy_init;
    uint32_t mpo_policy_initbsd;
    uint32_t mpo_policy_syscall;
    uint32_t mpo_system_check_sysctlbyname;
    uint32_t mpo_proc_check_inherit_ipc_ports;
    uint32_t mpo_vnode_check_rename;
    uint32_t mpo_kext_check_query;
    uint32_t mpo_iokit_check_nvram_get;
    uint32_t mpo_iokit_check_nvram_set;
    uint32_t mpo_iokit_check_nvram_delete;
    uint32_t mpo_proc_check_expose_task;
    uint32_t mpo_proc_check_set_host_special_port;
    uint32_t mpo_proc_check_set_host_exception_port;
    uint32_t mpo_exc_action_check_exception_send;
    uint32_t mpo_exc_action_label_associate;
    uint32_t mpo_exc_action_label_populate;
    uint32_t mpo_exc_action_label_destroy;
    uint32_t mpo_exc_action_label_init;
    uint32_t mpo_exc_action_label_update;
    uint32_t mpo_reserved1;
    uint32_t mpo_reserved2;
    uint32_t mpo_reserved3;
    uint32_t mpo_reserved4;
    uint32_t mpo_skywalk_flow_check_connect;
    uint32_t mpo_skywalk_flow_check_listen;
    uint32_t mpo_posixsem_check_create;
    uint32_t mpo_posixsem_check_open;
    uint32_t mpo_posixsem_check_post;
    uint32_t mpo_posixsem_check_unlink;
    uint32_t mpo_posixsem_check_wait;
    uint32_t mpo_posixsem_label_associate;
    uint32_t mpo_posixsem_label_destroy;
    uint32_t mpo_posixsem_label_init;
    uint32_t mpo_posixshm_check_create;
    uint32_t mpo_posixshm_check_mmap;
    uint32_t mpo_posixshm_check_open;
    uint32_t mpo_posixshm_check_stat;
    uint32_t mpo_posixshm_check_truncate;
    uint32_t mpo_posixshm_check_unlink;
    uint32_t mpo_posixshm_label_associate;
    uint32_t mpo_posixshm_label_destroy;
    uint32_t mpo_posixshm_label_init;
    uint32_t mpo_proc_check_debug;
    uint32_t mpo_proc_check_fork;
    uint32_t mpo_proc_check_get_task_name;
    uint32_t mpo_proc_check_get_task;
    uint32_t mpo_proc_check_getaudit;
    uint32_t mpo_proc_check_getauid;
    uint32_t mpo_proc_check_getlcid;
    uint32_t mpo_proc_check_mprotect;
    uint32_t mpo_proc_check_sched;
    uint32_t mpo_proc_check_setaudit;
    uint32_t mpo_proc_check_setauid;
    uint32_t mpo_proc_check_setlcid;
    uint32_t mpo_proc_check_signal;
    uint32_t mpo_proc_check_wait;
    uint32_t mpo_proc_label_destroy;
    uint32_t mpo_proc_label_init;
    uint32_t mpo_socket_check_accept;
    uint32_t mpo_socket_check_accepted;
    uint32_t mpo_socket_check_bind;
    uint32_t mpo_socket_check_connect;
    uint32_t mpo_socket_check_create;
    uint32_t mpo_socket_check_deliver;
    uint32_t mpo_socket_check_kqfilter;
    uint32_t mpo_socket_check_label_update;
    uint32_t mpo_socket_check_listen;
    uint32_t mpo_socket_check_receive;
    uint32_t mpo_socket_check_received;
    uint32_t mpo_socket_check_select;
    uint32_t mpo_socket_check_send;
    uint32_t mpo_socket_check_stat;
    uint32_t mpo_socket_check_setsockopt;
    uint32_t mpo_socket_check_getsockopt;
    uint32_t mpo_socket_label_associate_accept;
    uint32_t mpo_socket_label_associate;
    uint32_t mpo_socket_label_copy;
    uint32_t mpo_socket_label_destroy;
    uint32_t mpo_socket_label_externalize;
    uint32_t mpo_socket_label_init;
    uint32_t mpo_socket_label_internalize;
    uint32_t mpo_socket_label_update;
    uint32_t mpo_socketpeer_label_associate_mbuf;
    uint32_t mpo_socketpeer_label_associate_socket;
    uint32_t mpo_socketpeer_label_destroy;
    uint32_t mpo_socketpeer_label_externalize;
    uint32_t mpo_socketpeer_label_init;
    uint32_t mpo_system_check_acct;
    uint32_t mpo_system_check_audit;
    uint32_t mpo_system_check_auditctl;
    uint32_t mpo_system_check_auditon;
    uint32_t mpo_system_check_host_priv;
    uint32_t mpo_system_check_nfsd;
    uint32_t mpo_system_check_reboot;
    uint32_t mpo_system_check_settime;
    uint32_t mpo_system_check_swapoff;
    uint32_t mpo_system_check_swapon;
    uint32_t mpo_socket_check_ioctl;
    uint32_t mpo_sysvmsg_label_associate;
    uint32_t mpo_sysvmsg_label_destroy;
    uint32_t mpo_sysvmsg_label_init;
    uint32_t mpo_sysvmsg_label_recycle;
    uint32_t mpo_sysvmsq_check_enqueue;
    uint32_t mpo_sysvmsq_check_msgrcv;
    uint32_t mpo_sysvmsq_check_msgrmid;
    uint32_t mpo_sysvmsq_check_msqctl;
    uint32_t mpo_sysvmsq_check_msqget;
    uint32_t mpo_sysvmsq_check_msqrcv;
    uint32_t mpo_sysvmsq_check_msqsnd;
    uint32_t mpo_sysvmsq_label_associate;
    uint32_t mpo_sysvmsq_label_destroy;
    uint32_t mpo_sysvmsq_label_init;
    uint32_t mpo_sysvmsq_label_recycle;
    uint32_t mpo_sysvsem_check_semctl;
    uint32_t mpo_sysvsem_check_semget;
    uint32_t mpo_sysvsem_check_semop;
    uint32_t mpo_sysvsem_label_associate;
    uint32_t mpo_sysvsem_label_destroy;
    uint32_t mpo_sysvsem_label_init;
    uint32_t mpo_sysvsem_label_recycle;
    uint32_t mpo_sysvshm_check_shmat;
    uint32_t mpo_sysvshm_check_shmctl;
    uint32_t mpo_sysvshm_check_shmdt;
    uint32_t mpo_sysvshm_check_shmget;
    uint32_t mpo_sysvshm_label_associate;
    uint32_t mpo_sysvshm_label_destroy;
    uint32_t mpo_sysvshm_label_init;
    uint32_t mpo_sysvshm_label_recycle;
    uint32_t mpo_proc_notify_exit;
    uint32_t mpo_mount_check_snapshot_revert;
    uint32_t mpo_vnode_check_getattr;
    uint32_t mpo_mount_check_snapshot_create;
    uint32_t mpo_mount_check_snapshot_delete;
    uint32_t mpo_vnode_check_clone;
    uint32_t mpo_proc_check_get_cs_info;
    uint32_t mpo_proc_check_set_cs_info;
    uint32_t mpo_iokit_check_hid_control;
    uint32_t mpo_vnode_check_access;
    uint32_t mpo_vnode_check_chdir;
    uint32_t mpo_vnode_check_chroot;
    uint32_t mpo_vnode_check_create;
    uint32_t mpo_vnode_check_deleteextattr;
    uint32_t mpo_vnode_check_exchangedata;
    uint32_t mpo_vnode_check_exec;
    uint32_t mpo_vnode_check_getattrlist;
    uint32_t mpo_vnode_check_getextattr;
    uint32_t mpo_vnode_check_ioctl;
    uint32_t mpo_vnode_check_kqfilter;
    uint32_t mpo_vnode_check_label_update;
    uint32_t mpo_vnode_check_link;
    uint32_t mpo_vnode_check_listextattr;
    uint32_t mpo_vnode_check_lookup;
    uint32_t mpo_vnode_check_open;
    uint32_t mpo_vnode_check_read;
    uint32_t mpo_vnode_check_readdir;
    uint32_t mpo_vnode_check_readlink;
    uint32_t mpo_vnode_check_rename_from;
    uint32_t mpo_vnode_check_rename_to;
    uint32_t mpo_vnode_check_revoke;
    uint32_t mpo_vnode_check_select;
    uint32_t mpo_vnode_check_setattrlist;
    uint32_t mpo_vnode_check_setextattr;
    uint32_t mpo_vnode_check_setflags;
    uint32_t mpo_vnode_check_setmode;
    uint32_t mpo_vnode_check_setowner;
    uint32_t mpo_vnode_check_setutimes;
    uint32_t mpo_vnode_check_stat;
    uint32_t mpo_vnode_check_truncate;
    uint32_t mpo_vnode_check_unlink;
    uint32_t mpo_vnode_check_write;
    uint32_t mpo_vnode_label_associate_devfs;
    uint32_t mpo_vnode_label_associate_extattr;
    uint32_t mpo_vnode_label_associate_file;
    uint32_t mpo_vnode_label_associate_pipe;
    uint32_t mpo_vnode_label_associate_posixsem;
    uint32_t mpo_vnode_label_associate_posixshm;
    uint32_t mpo_vnode_label_associate_singlelabel;
    uint32_t mpo_vnode_label_associate_socket;
    uint32_t mpo_vnode_label_copy;
    uint32_t mpo_vnode_label_destroy;
    uint32_t mpo_vnode_label_externalize_audit;
    uint32_t mpo_vnode_label_externalize;
    uint32_t mpo_vnode_label_init;
    uint32_t mpo_vnode_label_internalize;
    uint32_t mpo_vnode_label_recycle;
    uint32_t mpo_vnode_label_store;
    uint32_t mpo_vnode_label_update_extattr;
    uint32_t mpo_vnode_label_update;
    uint32_t mpo_vnode_notify_create;
    uint32_t mpo_vnode_check_signature;
    uint32_t mpo_vnode_check_uipc_bind;
    uint32_t mpo_vnode_check_uipc_connect;
    uint32_t mpo_proc_check_run_cs_invalid;
    uint32_t mpo_proc_check_suspend_resume;
    uint32_t mpo_thread_userret;
    uint32_t mpo_iokit_check_set_properties;
    uint32_t mpo_system_check_chud;
    uint32_t mpo_vnode_check_searchfs;
    uint32_t mpo_priv_check;
    uint32_t mpo_priv_grant;
    uint32_t mpo_proc_check_map_anon;
    uint32_t mpo_vnode_check_fsgetpath;
    uint32_t mpo_iokit_check_open;
    uint32_t mpo_proc_check_ledger;
    uint32_t mpo_vnode_notify_rename;
    uint32_t mpo_vnode_check_setacl;
    uint32_t mpo_vnode_notify_deleteextattr;
    uint32_t mpo_system_check_kas_info;
    uint32_t mpo_vnode_check_lookup_preflight;
    uint32_t mpo_vnode_notify_open;
    uint32_t mpo_system_check_info;
    uint32_t mpo_pty_notify_grant;
    uint32_t mpo_pty_notify_close;
    uint32_t mpo_vnode_find_sigs;
    uint32_t mpo_kext_check_load;
    uint32_t mpo_kext_check_unload;
    uint32_t mpo_proc_check_proc_info;
    uint32_t mpo_vnode_notify_link;
    uint32_t mpo_iokit_check_filter_properties;
    uint32_t mpo_iokit_check_get_property;
};

uint32_t find_sbops(uint32_t region, uint8_t* kdata, size_t ksize) {
    char* seatbelt_sandbox_policy = memmem(kdata,
                                           ksize,
                                           "Seatbelt sandbox policy",
                                           strlen("Seatbelt sandbox policy"));
    olog("[*] seatbelt_sandbox_policy 0x%08lx\n",
           (uintptr_t)seatbelt_sandbox_policy);
    if (!seatbelt_sandbox_policy)
        return -1;
    
    uint32_t seatbelt =   (uintptr_t)seatbelt_sandbox_policy
                        - (uintptr_t)kdata
                        + region;
    olog("[*] seatbelt: 0x%08x\n", seatbelt);
    
    char* seatbelt_sandbox_policy_ptr = memmem(kdata,
                                               ksize,
                                               (char*)&seatbelt,
                                               sizeof(seatbelt));
    
    olog("[*] seatbelt_sandbox_policy_ptr 0x%08lx\n",
           (uintptr_t)seatbelt_sandbox_policy_ptr);
    if (!seatbelt_sandbox_policy_ptr)
        return -1;
    
    uint32_t ptr_to_seatbelt =   (uintptr_t)seatbelt_sandbox_policy_ptr
                               - (uintptr_t)kdata;
    uint32_t sbops = ptr_to_seatbelt + 0x24;
    olog("[*] found sbops: 0x%08x\n", sbops);
    
    return sbops;
}

uint8_t* dump_kernel(uint8_t* kdata, uint32_t len, task_t tfp0, uintptr_t kaslr_slide) {
    vm_size_t segment = 0x800;
    
    for (int i = 0; i < len / segment; i++) {
        
        vm_read_overwrite(tfp0,
                          UNSLID_BASE + kaslr_slide + (i * segment),
                          segment,
                          (vm_address_t)kdata + (i * segment),
                          &segment);
    }
    
    return kdata;
}

uint32_t kread_uint32(uint32_t addr, task_t tfp0) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(tfp0,
                      addr,
                      4,
                      (vm_address_t)&ret,
                      &bytesRead);
    return ret;
}

uint32_t hardcoded_allproc(void){
    //i should prob write a patchfinder rather than just using hardcoded offsets, but eh works anyway
        uint32_t allproc;
        if ([[NSArray arrayWithObjects:@"9.3.6",@"9.3.5",@"9.3.4",@"9.3.3",@"9.3.2",@"9.3.1",@"9.3", nil] containsObject:[[UIDevice currentDevice] systemVersion]]) {
            allproc = 0x45717c; //allproc offset for 9.3.X
            olog("using 0x45717c\n");
        } else if ([[NSArray arrayWithObjects:@"9.2.1",@"9.2", nil] containsObject:[[UIDevice currentDevice] systemVersion]]){
            allproc = 0x450128; //allproc offset for 9.2.X
            olog("using 0x450128\n");
        } else if ([[[UIDevice currentDevice] systemVersion] isEqualToString:@"9.1"]) {
            allproc = 0x458904; //allproc offset for 9.1
            olog("using 0x458904\n");
        } else {
            allproc = 0x457874; //allproc offset for 9.0.2 (likely 9.0.X)
            olog("using 0x457874\n");
        }
        olog("[*] found allproc: 0x%08x\n", allproc);
        return allproc;
}

bool unsandbox(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide) {
    olog("unsandboxing...\n");
    
    //i sure do love stealing code from p0laris
    //basically this like entire function is stolen
    uint8_t* kdata = NULL;
    kdata = malloc(32 * 1024 * 1024);
    dump_kernel(kdata, 32 * 1024 * 1024, tfp0, kaslr_slide);
    if (!kdata) {
        olog("fuck\n");
        exit(42);
    }
    olog("now...\n");
    
    uint32_t sbopsoffset = find_sbops(kernel_base, kdata, 32 * 1024 * 1024);
    olog("nuking sandbox at 0x%08lx\n", kernel_base + sbopsoffset);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0,4);
    vm_write(tfp0,kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0,4);
    
    olog("nuked sandbox\n");
    
    return true;
}


bool rootify(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide){
    olog("stealing kernel creds\n");
    
    uint32_t allproc_read = kread_uint32(kernel_base + hardcoded_allproc(), tfp0);
    olog("uint32_t allproc = 0x%08lx, uint32_t allproc_read = 0x%08x;\n",kernel_base + hardcoded_allproc(),allproc_read);
    
    uint32_t myproc = 0;
    uint32_t kernproc = 0;
    
    //thanks to Jake James for his awesome rootlessJB writeup, as well as spv
    if (allproc_read != 0) {
        while (myproc == 0 || kernproc == 0) {
            uint32_t kpid = kread_uint32(allproc_read + 8, tfp0); //go to next process
            if (kpid == getpid()) {
                myproc = allproc_read;
                olog("found myproc 0x%08x, %d\n", myproc, kpid);
            } else if (kpid == 0) {
                kernproc = allproc_read;
                olog("found kernproc 0x%08x, %d\n", kernproc, kpid);
            }
            allproc_read = kread_uint32(allproc_read, tfp0); //idk why this is needed but it is
        }
    } else {
        // fail
        return false;
    }
    
    uint32_t proc_ucred_offset;
    if ([[NSArray arrayWithObjects:@"9.3.6",@"9.3.5",@"9.3.4",@"9.3.3",@"9.3.2",@"9.3.1",@"9.3", nil] containsObject:[[UIDevice currentDevice] systemVersion]]) {
        proc_ucred_offset = 0xa4;
        olog("using 0xa4\n");
    } else if ([[NSArray arrayWithObjects:@"9.2.1",@"9.2",@"9.1", nil] containsObject:[[UIDevice currentDevice] systemVersion]]) {
        proc_ucred_offset = 0x98;
        olog("using 0x98\n");
    } else {
        proc_ucred_offset = 0x8c;
        olog("using 0x8c\n");
    }
    
    uint32_t kern_ucred = kread_uint32(kernproc + proc_ucred_offset, tfp0);
    olog("uint32_t kern_ucred = 0x%08x;\n", kern_ucred);
    
    vm_write(tfp0,
             myproc + proc_ucred_offset,
             (vm_offset_t)&kern_ucred,
             4); //patch our ucred with kern ucred
    
    setuid(0);
    
    olog("got root\n");
    
    return true;

}
/*
uint32_t find_kernel_pmap(void) {
    uint32_t pmap_addr;
    if ([[NSArray arrayWithObjects:@"9.3.6",@"9.3.5",@"9.3.4",@"9.3.3",@"9.3.2",@"9.3.1",@"9.3", nil] containsObject:[[UIDevice currentDevice] systemVersion]]) {
        pmap_addr = 0x003F6454; //for A5. For A6 offset is 0x003FE454
    } else if ([[NSArray arrayWithObjects:@"9.2.1",@"9.2", nil] containsObject:[[UIDevice currentDevice] systemVersion]]) {
        pmap_addr = 0x003EF444;
    } else if ([[[UIDevice currentDevice] systemVersion]isEqualToString:@"9.1"]) {
        pmap_addr = 0x003F8444;
    } else {
        pmap_addr = 0x003F7444;
    }
    printf("using offset 0x%08x for pmap",pmap_addr);
    return pmap_addr + kernel_base;
}
 
void patch_kernel_pmap(void) {
}*/
 
bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide) {
    
    //patch_kernel_pmap();
    
    uint32_t before = -1;
    uint32_t after = -1;
    
    printf("check pmap patch\n");
    
    before = kread_uint32(kernel_base, tfp0);
    //kwrite_uint32(kernel_base, 0x41424344, tfp0);
    after = kread_uint32(kernel_base, tfp0);
    //kwrite_uint32(kernel_base, before, tfp0);
    
    if (before != after && /* before == 0xfeedface && */ after == 0x41424344) {
        printf("pmap patched!");
    } else {
        printf("pmap patch failed");
        return false;
    }
    return true;
}
