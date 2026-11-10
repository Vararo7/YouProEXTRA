#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dispatch/dispatch.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

/*
 * Passive diagnostic for YouTube 21.44.4, used WITH the working
 * one-instruction quality-key patch. No server traffic or content is logged.
 * It records selector results, and the two stack values at the precise
 * +[NSArray arrayWithObjects:count:] call. Remove this tweak after testing.
 */
#define MAX_HOOKS 512
#define MAX_EVENTS 100
#define MAX_IMPORTANT 30

typedef struct {
    __unsafe_unretained Class owner; /* class or metaclass that directly implements selector */
    SEL selector;
    IMP original;
} ProbeHook;

static ProbeHook g_hooks[MAX_HOOKS];
static unsigned g_hookCount = 0;
static NSMutableArray<NSString *> *g_events;
static NSMutableArray<NSString *> *g_importantEvents;
static volatile uint64_t g_providerCalls = 0;
static volatile uint64_t g_wifiCalls = 0;
static volatile uint64_t g_mobileCalls = 0;
static volatile uint64_t g_wifiNilCalls = 0;
static volatile uint64_t g_mobileNilCalls = 0;
static BOOL g_arrayHookInstalled = NO;
static BOOL g_alertScheduled = NO;
static BOOL g_alertShown = NO;
static BOOL g_arrayObserved = NO;
static id (*g_origArray)(id, SEL, const id *, NSUInteger);
static __thread BOOL g_inHook = NO;

static NSString *ProbeObjectClass(id obj) {
    if (!obj) return @"nil";
    Class c = object_getClass(obj);
    const char *n = c ? class_getName(c) : NULL;
    return n ? [NSString stringWithUTF8String:n] : @"unknown";
}

static void ProbeShowAlertAttempts(int retries);

static void ProbeScheduleAlert(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_alertScheduled || g_alertShown) return;
        g_alertScheduled = YES;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{ ProbeShowAlertAttempts(0); });
    });
}

static void ProbeRecord(NSString *event, BOOL important) {
    if (!event) return;
    NSLog(@"[YTQualityProbe] %@", event);
    @synchronized (g_events) {
        if (g_events.count >= MAX_EVENTS) [g_events removeObjectAtIndex:0];
        [g_events addObject:event];
        // Preserve the FIRST important results; routine calls cannot push them out.
        if (important && g_importantEvents.count < MAX_IMPORTANT) {
            [g_importantEvents addObject:event];
        }
    }
    if (important) ProbeScheduleAlert();
}

static UIViewController *ProbeTopController(void) {
    UIWindow *window = nil;
    UIApplication *app = [UIApplication sharedApplication];
    for (UIScene *scene in app.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        if (scene.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *candidate in ((UIWindowScene *)scene).windows) {
            if (candidate.isKeyWindow) { window = candidate; break; }
        }
        if (window) break;
    }
    // Fallback for inactive/transitional scenes (without deprecated keyWindow).
    if (!window) {
        for (UIScene *scene in app.connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *candidate in ((UIWindowScene *)scene).windows) {
                if (candidate.isKeyWindow || candidate.rootViewController) {
                    window = candidate;
                    break;
                }
            }
            if (window) break;
        }
    }
    UIViewController *controller = window.rootViewController;
    while (controller.presentedViewController) {
        controller = controller.presentedViewController;
    }
    return controller;
}

static NSString *ProbeAllEvents(void) {
    @synchronized (g_events) {
        NSString *important = g_importantEvents.count > 0
            ? [g_importantEvents componentsJoinedByString:@"\n"]
            : @"(none recorded)";
        NSString *events = [g_events componentsJoinedByString:@"\n"];
        return [NSString stringWithFormat:
            @"YT QUALITY PROBE 0.2 | YouTube 21.44.4 + patched quality array\n"
             @"Runtime URL/profile/content NOT captured\n"
             @"COUNTS: keysProvider=%llu wifiGetter=%llu (nil=%llu) mobileGetter=%llu (nil=%llu)\n"
             @"HOOKS: installed=%u NSArray=%@ exactArrayCallSeen=%@\n\n"
             @"FIRST IMPORTANT EVENTS (never displaced):\n%@\n\n"
             @"RECENT EVENTS:\n%@",
            (unsigned long long)g_providerCalls,
            (unsigned long long)g_wifiCalls, (unsigned long long)g_wifiNilCalls,
            (unsigned long long)g_mobileCalls, (unsigned long long)g_mobileNilCalls,
            g_hookCount, g_arrayHookInstalled ? @"yes" : @"no",
            g_arrayObserved ? @"yes" : @"no", important, events];
    }
}

static void ProbeShowAlertAttempts(int retries) {
    if (g_alertShown) return;
    UIViewController *controller = ProbeTopController();
    if (!controller || [controller isKindOfClass:[UIAlertController class]]) {
        if (retries < 12) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{ ProbeShowAlertAttempts(retries + 1); });
        }
        return;
    }
    g_alertShown = YES;
    NSString *events = ProbeAllEvents();
    NSArray<NSString *> *lines = [events componentsSeparatedByString:@"\n"];
    NSUInteger start = lines.count > 9 ? lines.count - 9 : 0;
    NSString *summary = [[lines subarrayWithRange:NSMakeRange(start, lines.count - start)]
                         componentsJoinedByString:@"\n"];
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"YouTube quality diagnostic"
        message:[NSString stringWithFormat:@"Quality diagnostic: copy the full report and paste it into ChatGPT.\n\n%@", summary]
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Copy full report"
        style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
            [UIPasteboard generalPasteboard].string = ProbeAllEvents();
        }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Dismiss"
        style:UIAlertActionStyleCancel handler:nil]];
    [controller presentViewController:alert animated:YES completion:nil];
}

static IMP ProbeFindOriginal(id receiver, SEL selector) {
    Class c = object_getClass(receiver);
    for (; c != Nil; c = class_getSuperclass(c)) {
        for (unsigned i = 0; i < g_hookCount; ++i) {
            if (g_hooks[i].owner == c && g_hooks[i].selector == selector)
                return g_hooks[i].original;
        }
    }
    return NULL;
}

static id ProbeGetter(id receiver, SEL selector) {
    IMP imp = ProbeFindOriginal(receiver, selector);
    if (!imp) {
        NSLog(@"[YTQualityProbe] ERROR: missing original for %@ on %@",
              NSStringFromSelector(selector), ProbeObjectClass(receiver));
        return nil;
    }
    id result = ((id (*)(id, SEL))imp)(receiver, selector);
    const char *sel = sel_getName(selector);
    BOOL isProvider = strcmp(sel, "keysProvider") == 0;
    BOOL isWifi = strcmp(sel, "persistentVideoQualityWifiKey") == 0;
    BOOL isMobile = strcmp(sel, "persistentVideoQualityMobileKey") == 0;
    uint64_t callNumber = 0;
    if (isProvider) callNumber = __sync_add_and_fetch(&g_providerCalls, 1);
    if (isWifi) {
        callNumber = __sync_add_and_fetch(&g_wifiCalls, 1);
        if (!result) __sync_add_and_fetch(&g_wifiNilCalls, 1);
    }
    if (isMobile) {
        callNumber = __sync_add_and_fetch(&g_mobileCalls, 1);
        if (!result) __sync_add_and_fetch(&g_mobileNilCalls, 1);
    }
    if (!g_inHook) {
        g_inHook = YES;
        BOOL important = (!result && (isProvider || isWifi || isMobile));
        // Don't let frequent keysProvider calls drown out the useful results.
        BOOL shouldLog = important || callNumber <= (isProvider ? 3 : 12);
        if (shouldLog) {
            ProbeRecord([NSString stringWithFormat:@"%@ call=%llu receiver=%@ return=%@ pointer=%p",
                         NSStringFromSelector(selector), (unsigned long long)callNumber,
                         ProbeObjectClass(receiver), ProbeObjectClass(result),
                         (__bridge void *)result], important);
        }
        g_inHook = NO;
    }
    return result;
}

static void ProbeHookMethodList(Class owner) {
    if (!owner) return;
    unsigned int count = 0;
    Method *methods = class_copyMethodList(owner, &count);
    for (unsigned int i = 0; i < count; ++i) {
        Method m = methods[i];
        SEL selector = method_getName(m);
        const char *name = sel_getName(selector);
        if (strcmp(name, "keysProvider") != 0 &&
            strcmp(name, "persistentVideoQualityWifiKey") != 0 &&
            strcmp(name, "persistentVideoQualityMobileKey") != 0) continue;
        char returnType[32] = {0};
        method_getReturnType(m, returnType, sizeof(returnType));
        if (returnType[0] != '@' || method_getNumberOfArguments(m) != 2) continue;
        if (g_hookCount >= MAX_HOOKS) break;
        IMP old = method_getImplementation(m);
        g_hooks[g_hookCount++] = (ProbeHook){owner, selector, old};
        method_setImplementation(m, (IMP)ProbeGetter);
    }
    if (methods) free(methods);
}

/* Called specifically when our patched YouTube calls NSArray at +0x4919b0.
 * Both pointers are already on YouTube's stack, even when the patched count=0.
 * We log addresses only; we do NOT attempt to dereference the values. */
static id ProbeArray(id receiver, SEL selector, const id *objects, NSUInteger count) {
    uintptr_t ret = (uintptr_t)__builtin_return_address(0);
    uintptr_t expected = (uintptr_t)(0x1004919B4ULL + _dyld_get_image_vmaddr_slide(0));
    if (ret == expected && !g_arrayObserved) {
        g_arrayObserved = YES;
        // Reading the two stack slots under ARC without illegal pointer casts.
        id __unsafe_unretained wifi = objects ? objects[0] : nil;
        id __unsafe_unretained mobile = objects ? objects[1] : nil;
        ProbeRecord([NSString stringWithFormat:
                     @"EXACT YouTube +0x4919b0 array call: count=%lu, wifi[0]=%p, mobile[1]=%p",
                     (unsigned long)count, (__bridge void *)wifi, (__bridge void *)mobile], YES);
    }
    return g_origArray(receiver, selector, objects, count);
}

static void ProbeInstall(void) {
    g_events = [[NSMutableArray alloc] init];
    g_importantEvents = [[NSMutableArray alloc] init];
    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    for (unsigned int i = 0; i < classCount; ++i) {
        ProbeHookMethodList(classes[i]);
        ProbeHookMethodList(object_getClass(classes[i]));
    }
    if (classes) free(classes);

    Method arrayMethod = class_getClassMethod([NSArray class], @selector(arrayWithObjects:count:));
    g_arrayHookInstalled = arrayMethod != NULL;
    if (arrayMethod) {
        g_origArray = (id (*)(id, SEL, const id *, NSUInteger))method_getImplementation(arrayMethod);
        method_setImplementation(arrayMethod, (IMP)ProbeArray);
    }
    ProbeRecord([NSString stringWithFormat:@"Probe installed: %u getter implementations; NSArray hook=%@; YouTube slide=0x%llx",
                 g_hookCount, arrayMethod ? @"yes" : @"no",
                 (unsigned long long)_dyld_get_image_vmaddr_slide(0)], NO);
}

__attribute__((constructor)) static void ProbeInitialize(void) {
    dispatch_async(dispatch_get_main_queue(), ^{ ProbeInstall(); });
}
