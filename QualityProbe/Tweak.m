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
#define MAX_EVENTS 60

typedef struct {
    __unsafe_unretained Class owner; /* class or metaclass that directly implements selector */
    SEL selector;
    IMP original;
} ProbeHook;

static ProbeHook g_hooks[MAX_HOOKS];
static unsigned g_hookCount = 0;
static NSMutableArray<NSString *> *g_events;
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
    if (!window) window = app.keyWindow;
    UIViewController *controller = window.rootViewController;
    while (controller.presentedViewController) {
        controller = controller.presentedViewController;
    }
    return controller;
}

static NSString *ProbeAllEvents(void) {
    @synchronized (g_events) {
        NSString *events = [g_events componentsJoinedByString:@"\n"];
        return [NSString stringWithFormat:
            @"YT QUALITY PROBE 0.1 | YouTube 21.44.4 + patched quality array\n"
             @"Runtime URL/profile/content NOT captured\n\n%@", events];
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
        message:[NSString stringWithFormat:@"Captured the quality-key failure path. Copy the full report, then paste it into ChatGPT.\n\n%@", summary]
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
    if (!g_inHook) {
        g_inHook = YES;
        const char *sel = sel_getName(selector);
        BOOL important = (!result && (strcmp(sel, "keysProvider") == 0 ||
                                           strcmp(sel, "persistentVideoQualityWifiKey") == 0));
        ProbeRecord([NSString stringWithFormat:@"%@ receiver=%@ return=%@ pointer=%p",
                     NSStringFromSelector(selector), ProbeObjectClass(receiver),
                     ProbeObjectClass(result), (__bridge void *)result], important);
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
        const void *wifi = objects ? ((const void * const *)objects)[0] : NULL;
        const void *mobile = objects ? ((const void * const *)objects)[1] : NULL;
        ProbeRecord([NSString stringWithFormat:
                     @"EXACT YouTube +0x4919b0 array call: count=%lu, wifi[0]=%p, mobile[1]=%p",
                     (unsigned long)count, wifi, mobile], YES);
    }
    return g_origArray(receiver, selector, objects, count);
}

static void ProbeInstall(void) {
    g_events = [[NSMutableArray alloc] init];
    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    for (unsigned int i = 0; i < classCount; ++i) {
        ProbeHookMethodList(classes[i]);
        ProbeHookMethodList(object_getClass(classes[i]));
    }
    if (classes) free(classes);

    Class arrayMeta = object_getClass([NSArray class]);
    Method arrayMethod = class_getClassMethod([NSArray class], @selector(arrayWithObjects:count:));
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
