//
//  jailbreak.h
//  openpwnage
//
//  Created by Zachary Keffaber on 4/24/22.
//

#ifndef jailbreak_h
#define jailbreak_h

bool rootify(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide);
#endif /* jailbreak_h */
