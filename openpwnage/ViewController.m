//
//  ViewController.m
//  openpwnage
//
//  Created by Zachary Keffaber on 4/20/22.
//

#import "ViewController.h"
#import <sys/utsname.h>

#import "jailbreak.h"

uintptr_t kernel_base    = -1;
uintptr_t kaslr_slide    = -1;
task_t tfp0                = 0;
#define UNSLID_BASE 0x80001000

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *jbButton;
@property (weak, nonatomic) IBOutlet UITextView *consoleView;
-(void)openpwnageConsoleLog:(NSString*)textToLog;
@end

@implementation ViewController

static id static_consoleView = nil;
- (void)viewDidLoad {
    [super viewDidLoad];
    //static_consoleView = _consoleView;
    [self setNeedsStatusBarAppearanceUpdate];
    // Do any additional setup after loading the view.
    _jbButton.layer.cornerRadius = 5.0;
    struct utsname systemInfo;
    uname(&systemInfo);
    
    _consoleView.text = [NSString stringWithFormat:@"[*]openpwnage running on %@ with iOS %@\n", [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding], [[UIDevice currentDevice] systemVersion]];
}
- (IBAction)jailbreakButtonPressed:(id)sender {
    NSLog(@"button pressed");
    //self.view.backgroundColor = [UIColor systemGreenColor];
    [self openpwnageConsoleLog:@"[*]starting jailbreak...\n"];
    // task_t kernel_task = 0;
    // task_for_pid(mach_task_self(), 0, &kernel_task);
    tfp0 = get_kernel_task();
    [self openpwnageConsoleLog:@"[*]we tried getting tfp0, and holy shit it actually worked\n"];
    [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]tfp0=0x%x\n", tfp0]];
    [self openpwnageConsoleLog:@"[*]we should try getting kbase now, hold on...\n"];
    kernel_base = kbase();
    [self openpwnageConsoleLog:@"[*]ayo, yet another success!\n"];
    [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]huzzah, kbase=0x%08lx\n", kernel_base]];
    [self openpwnageConsoleLog:@"[*]one more thing we need to get before patching: kaslr slide.\n"];
    kaslr_slide = kernel_base - UNSLID_BASE;
    [self openpwnageConsoleLog:@"[*]WOOO! Now we talkin'!\n"];
    [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]slide=0x%08lx\n", kaslr_slide]];
    [self openpwnageConsoleLog:@"[*]this is great and all, but now time for actual shit\n"];
    [self openpwnageConsoleLog:@"[*]obtaining root...\n"];
    rootify(tfp0, kernel_base, kaslr_slide);
    [self openpwnageConsoleLog:@"[*]we root baby\n"];
    [self openpwnageConsoleLog:@"[*]cleaning up exploit...\n"];
    exploit_cleanup(tfp0);
    [self openpwnageConsoleLog:@"[*]nice and tidy\n"];
    [self openpwnageConsoleLog:@"[*]that's all for know. next step is prob pmap patch\n"];
    //go();
}

-(void)openpwnageConsoleLog: (NSString*)textToLog {
    NSLog(@"%@", [[NSString alloc]initWithString:textToLog]);
    NSMutableString *mutableLog = [_consoleView.text mutableCopy];
    _consoleView.text = [[NSString alloc]initWithString:[mutableLog stringByAppendingString:textToLog]];
}

@end
