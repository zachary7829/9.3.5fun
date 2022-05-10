//
//  ViewController.m
//  openpwnage
//
//  Created by Zachary Keffaber on 4/20/22.
//

#import "ViewController.h"
#import <sys/utsname.h>

#import "jailbreak.h"

#define UNSLID_BASE 0x80001000

#define UIColorFromRGB(rgbValue) [UIColor \
colorWithRed:((float)((rgbValue & 0xFF0000) >> 16))/255.0 \
green:((float)((rgbValue & 0xFF00) >> 8))/255.0 \
blue:((float)(rgbValue & 0xFF))/255.0 alpha:1.0]

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UILabel *notSupportedLabel;
@property (weak, nonatomic) IBOutlet UIButton *jbButton;
@property (weak, nonatomic) IBOutlet UITextView *consoleView;
-(void)openpwnageConsoleLog:(NSString*)textToLog;
@end

@implementation ViewController

id param_;

static id static_consoleView = nil;
-(void)viewDidLoad {
    [super viewDidLoad];
    param_ = self;
    //static_consoleView = _consoleView;
    [self setNeedsStatusBarAppearanceUpdate];
    // Do any additional setup after loading the view.
    _jbButton.layer.cornerRadius = 5.0;
    _consoleView.layer.cornerRadius = 10.0;
    struct utsname systemInfo;
    uname(&systemInfo);
    
    _consoleView.text = [NSString stringWithFormat:@"[*]openpwnage running on %@ with iOS %@\n", [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding], [[UIDevice currentDevice] systemVersion]];
    //olog("olog functional!");
    
    NSArray *supportedDevices = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPad3,4",@"iPad3,5",@"iPad3,6",@"iPhone4,1",@"iPhone5,1",@"iPhone5,2",@"iPhone5,3",@"iPhone5,4",@"iPod5,1",@"iPod7,1", nil];
    //supports all 32bit devices on 9.0-9.3.5 (the kinfo leak works on 8.0-8.4.1 but the mach_ports_register() bug (CVE-2016-4669) doesn't), aka iPad 2, iPad Mini 1, iPad 3, iPad 4, iPhone 4S, iPhone 5, iPhone 5C, iPod Touch 5, iPod Touch 6
    if([supportedDevices containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]){
        if ([[[UIDevice currentDevice] systemVersion] integerValue] != 9) {
            [self openpwnageConsoleLog:@"[*]your device is supported by openpwnage, but your iOS version is not\n"];
            int dadetectedfw = [[[UIDevice currentDevice] systemVersion] integerValue];
            [self openpwnageConsoleLog:[NSString stringWithFormat:@"%d",dadetectedfw]];
            [self openpwnageConsoleLog:@"[*]openpwnage supports 32bit 9.0-9.3.6 only at the moment\n"];
            _jbButton.hidden = 1;
            _consoleView.backgroundColor = UIColorFromRGB(0xF9c9c9);
        } else {
            _notSupportedLabel.hidden = 1;
        }
    } else {
        [self openpwnageConsoleLog:@"[*]your device is not supported by openpwnage\n"];
        _jbButton.hidden = 1;
        _consoleView.backgroundColor = UIColorFromRGB(0xF9c9c9);
    }
}
- (IBAction)jailbreakButtonPressed:(id)sender {
    NSLog(@"button pressed");
    [self openpwnageConsoleLog:@"[*]starting jailbreak...\n"];
    task_t tfp0 = get_kernel_task();
    [self openpwnageConsoleLog:@"[*]we tried getting tfp0, and holy shit it actually worked\n"];
    [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]tfp0=0x%x\n", tfp0]];
    [self openpwnageConsoleLog:@"[*]we should try getting kbase now, hold on...\n"];
    uintptr_t kernel_base = kbase();
    [self openpwnageConsoleLog:@"[*]ayo, yet another success!\n"];
    [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]huzzah, kbase=0x%08lx\n", kernel_base]];
    [self openpwnageConsoleLog:@"[*]one more thing we need to get before patching: kaslr slide.\n"];
    uintptr_t kaslr_slide = kernel_base - UNSLID_BASE;
    [self openpwnageConsoleLog:@"[*]WOOO! Now we talkin'!\n"];
    [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]slide=0x%08lx\n", kaslr_slide]];
    [self openpwnageConsoleLog:@"[*]this is great and all, but now time for actual shit\n"];
    [self openpwnageConsoleLog:@"[*]obtaining root...\n"];
    if (rootify(tfp0, kernel_base, kaslr_slide)) {
        [self openpwnageConsoleLog:@"[*]we root baby\n"];
        [self openpwnageConsoleLog:@"[*]now, time to nuke sandbox\n"];
        if (unsandbox(tfp0, kernel_base, kaslr_slide)) {
            [self openpwnageConsoleLog:@"[*]no need to worry about sandbox anymore\n"];
        } else {
            [self openpwnageConsoleLog:@"[*]failed to nuke sandbox\n"];
        }
    } else {
        [self openpwnageConsoleLog:@"[*]failed to get root :(\n"];
    }
    [self openpwnageConsoleLog:@"[*]cleaning up exploit...\n"];
    exploit_cleanup(tfp0);
    [self openpwnageConsoleLog:@"[*]nice and tidy\n"];
    [self openpwnageConsoleLog:@"[*]that's all for know. more soon (hopefully)\n"];
    //go();
}

-(void)openpwnageConsoleLog: (NSString*)textToLog {
    NSLog(@"(olog)%@", [[NSString alloc]initWithString:textToLog]);
    NSMutableString *mutableLog = [_consoleView.text mutableCopy];
    _consoleView.text = [[NSString alloc]initWithString:[mutableLog stringByAppendingString:textToLog]];
}

void openpwnageCLog(NSString* textToLog) {
    NSLog(@"openpwnageCLog\n");
    //NSLog(@"%@", [[NSString alloc]initWithString:textToLog]);
    dispatch_sync(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        [param_ openpwnageConsoleLog:textToLog];
    });
}

@end

/*
 [self openpwnageConsoleLog:@"[*]i wonder if pmap patch works\n"];
 if (is_pmap_patch_success(tfp0, kernel_base, kaslr_slide)) {
     [self openpwnageConsoleLog:@"[*]pmap success! woo\n"];
 } else {
     [self openpwnageConsoleLog:@"[*]nope :/\n"];
 }
 */
