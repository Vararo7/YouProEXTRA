#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dispatch/dispatch.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

/*
 * Targeted call-site diagnostic for UNPATCHED YouTube 21.44.4.
 * v0.6 snapshots caller-preserved ARM64 registers at the verified array call.
 * No runtime executable-page hooking or modification.
 * Captures the original two array elements at the precise failing call.
 * Returns an empty array ONLY when that exact call contains a nil object.
 * No video, URL, profile, or object string values are intentionally logged.
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
static volatile uint64_t g_siteProviderCalls = 0;
static volatile uint64_t g_siteWifiCalls = 0;
static volatile uint64_t g_siteMobileCalls = 0;
static volatile uint64_t g_siteProviderNil = 0;
static volatile uint64_t g_siteWifiNil = 0;
static volatile uint64_t g_siteMobileNil = 0;
static BOOL g_arrayHookInstalled = NO;
static BOOL g_alertScheduled = NO;
static BOOL g_alertShown = NO;
static BOOL g_arrayObserved = NO;
static volatile uint64_t g_targetCalls = 0;
static volatile uint64_t g_targetCount2 = 0;
static volatile uint64_t g_targetNil0 = 0;
static volatile uint64_t g_targetNil1 = 0;
static volatile uint64_t g_targetFallbacks = 0;
static volatile uint64_t g_targetPassThrough = 0;
static volatile uint64_t g_targetUnexpectedCount = 0;
static volatile uint64_t g_snapshotCalls = 0;
static volatile uint64_t g_nilStoredReceiver = 0;
static volatile uint64_t g_nilProviderRegister = 0;
static volatile uint64_t g_snapshotMismatches = 0;
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
            @"YT QUALITY PROBE 0.6 | YouTube 21.44.4 UNPATCHED original array\n"
             @"No runtime URL/profile/content or object string values captured\n"
             @"GETTERS: keysProvider=%llu wifiGetter=%llu (nil=%llu) mobileGetter=%llu (nil=%llu)\n"
             @"ORIGINAL CALLSITE MATCHES: keysProvider=%llu (nil=%llu) wifiGetter=%llu (nil=%llu) mobileGetter=%llu (nil=%llu)\n"
             @"HOOKS: installed=%u NSArray=%@ exactArrayCallSeen=%@\n"
             @"REGISTER SNAPSHOT: calls=%llu storedReceiverNil=%llu providerRegisterNil=%llu keyRegisterMismatch=%llu\n"
             @"EXACT CALLS: total=%llu count2=%llu nil0=%llu nil1=%llu emptyFallback=%llu normalPass=%llu unexpectedCount=%llu\n\n"
             @"FIRST IMPORTANT EVENTS (never displaced):\n%@\n\n"
             @"RECENT EVENTS:\n%@",
            (unsigned long long)g_providerCalls,
            (unsigned long long)g_wifiCalls, (unsigned long long)g_wifiNilCalls,
            (unsigned long long)g_mobileCalls, (unsigned long long)g_mobileNilCalls,
            (unsigned long long)g_siteProviderCalls, (unsigned long long)g_siteProviderNil,
            (unsigned long long)g_siteWifiCalls, (unsigned long long)g_siteWifiNil,
            (unsigned long long)g_siteMobileCalls, (unsigned long long)g_siteMobileNil,
            g_hookCount, g_arrayHookInstalled ? @"yes" : @"no",
            g_arrayObserved ? @"yes" : @"no",
            (unsigned long long)g_snapshotCalls,
            (unsigned long long)g_nilStoredReceiver,
            (unsigned long long)g_nilProviderRegister,
            (unsigned long long)g_snapshotMismatches,
            (unsigned long long)g_targetCalls,
            (unsigned long long)g_targetCount2,
            (unsigned long long)g_targetNil0,
            (unsigned long long)g_targetNil1,
            (unsigned long long)g_targetFallbacks,
            (unsigned long long)g_targetPassThrough,
            (unsigned long long)g_targetUnexpectedCount,
            important, events];
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
    // objc_msgSend normally tail-calls its IMP: LR points into the original
    // YouTube callsite. If another tweak calls an IMP directly, LR differs.
    // This records the caller before our probe performs any Objective-C calls.
    uintptr_t caller = (uintptr_t)__builtin_return_address(0);
    uintptr_t imageBase = 0x100000000ULL + (uintptr_t)_dyld_get_image_vmaddr_slide(0);
    uintptr_t callerOffset = caller >= imageBase && caller < imageBase + 0x0b7b0000ULL
        ? caller - imageBase : 0;
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
    BOOL exactProvider = isProvider && callerOffset == 0x491974ULL;
    BOOL exactWifi = isWifi && callerOffset == 0x491980ULL;
    BOOL exactMobile = isMobile && callerOffset == 0x491994ULL;
    BOOL fromCrashPath = exactProvider || exactWifi || exactMobile;
    if (exactProvider) {
        __sync_add_and_fetch(&g_siteProviderCalls, 1);
        if (!result) __sync_add_and_fetch(&g_siteProviderNil, 1);
    }
    if (exactWifi) {
        __sync_add_and_fetch(&g_siteWifiCalls, 1);
        if (!result) __sync_add_and_fetch(&g_siteWifiNil, 1);
    }
    if (exactMobile) {
        __sync_add_and_fetch(&g_siteMobileCalls, 1);
        if (!result) __sync_add_and_fetch(&g_siteMobileNil, 1);
    }
    if (!g_inHook) {
        g_inHook = YES;
        BOOL important = fromCrashPath || (!result && (isProvider || isWifi || isMobile));
        // Preserve the actual crash-path events and show the return addresses
        // of every observed quality getter, not only their aggregate counts.
        BOOL shouldLog = important || callNumber <= (isProvider ? 3 : 12);
        if (shouldLog) {
            NSString *site = callerOffset
                ? [NSString stringWithFormat:@"YouTube+0x%llx", (unsigned long long)callerOffset]
                : @"outside-YouTube";
            ProbeRecord([NSString stringWithFormat:
                @"%@ call=%llu source=%@%@ receiver=%@ return=%@ pointer=%p",
                NSStringFromSelector(selector), (unsigned long long)callNumber,
                site, fromCrashPath ? @" [EXACT_CRASH_PATH]" : @"",
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

/*
 * ProbeArrayEntry is a tiny ABI-preserving shim installed through the SAME
 * Objective-C method replacement that worked in probe 0.4. It does not alter
 * YouTube's executable memory (unlike the failed native hook in v0.5).
 *
 * ARM64: at the exact YouTube+0x4919b0 call, x20 = owning internal object;
 * x22 = keysProvider result; x23 = mobile key result;
 * x24 = Wi-Fi key result. These are callee-saved registers, so the Objective-C
 * dispatch machinery must preserve them. We copy them into the unused
 * argument registers x4..x7, then tail-branch to our normal Objective-C IMP.
 * The original lr/sp/ABI are unchanged. On other callsites we pass through.
 *
 * This is still device-untested, version-specific instrumentation.
 */
extern id ProbeArrayEntry(id receiver, SEL selector, const id *objects, NSUInteger count);
id ProbeArrayWithRegisters(id receiver, SEL selector, const id *objects, NSUInteger count,
                           uintptr_t ownerX20, uintptr_t providerX22,
                           uintptr_t mobileX23, uintptr_t wifiX24)
    __attribute__((used, noinline));

__asm__(
    ".text\n"
    ".p2align 2\n"
    ".globl _ProbeArrayEntry\n"
    "_ProbeArrayEntry:\n"
    "mov x4, x20\n"
    "mov x5, x22\n"
    "mov x6, x23\n"
    "mov x7, x24\n"
    "b _ProbeArrayWithRegisters\n"
);

/* Return address from the original BL at YouTube+0x4919b0 is +0x4919b4. */
id ProbeArrayWithRegisters(id receiver, SEL selector, const id *objects, NSUInteger count,
                           uintptr_t ownerX20, uintptr_t providerX22,
                           uintptr_t mobileX23, uintptr_t wifiX24) {
    uintptr_t ret = (uintptr_t)__builtin_return_address(0);
    uintptr_t expected = (uintptr_t)(0x1004919B4ULL + _dyld_get_image_vmaddr_slide(0));
    if (ret != expected) return g_origArray(receiver, selector, objects, count);

    g_arrayObserved = YES;
    uint64_t callNumber = __sync_add_and_fetch(&g_targetCalls, 1);
    if (count != 2) {
        __sync_add_and_fetch(&g_targetUnexpectedCount, 1);
        ProbeRecord([NSString stringWithFormat:
            @"EXACT CALL #%llu UNEXPECTED count=%lu; no fallback or register dereference",
            (unsigned long long)callNumber, (unsigned long)count], YES);
        return g_origArray(receiver, selector, objects, count);
    }
    __sync_add_and_fetch(&g_targetCount2, 1);

    id __unsafe_unretained first = objects ? objects[0] : nil;
    id __unsafe_unretained second = objects ? objects[1] : nil;
    uintptr_t firstPtr = (uintptr_t)(__bridge void *)first;
    uintptr_t secondPtr = (uintptr_t)(__bridge void *)second;
    BOOL firstNil = (first == nil);
    BOOL secondNil = (second == nil);
    if (firstNil) __sync_add_and_fetch(&g_targetNil0, 1);
    if (secondNil) __sync_add_and_fetch(&g_targetNil1, 1);
    BOOL needsFallback = firstNil || secondNil;
    if (needsFallback) __sync_add_and_fetch(&g_targetFallbacks, 1);
    else __sync_add_and_fetch(&g_targetPassThrough, 1);

    __sync_add_and_fetch(&g_snapshotCalls, 1);
    // The exact caller has just used x20 to access multiple valid fields.
    // Read ONLY its +0x18 field and ONLY after confirming the exact return PC.
    // Avoid touching arbitrary object memory or interpreting unknown pointers
    // as Objective-C objects. We record pointer presence, not contents.
    uintptr_t storedReceiver = 0;
    BOOL ownerNull = ownerX20 == 0;
    if (!ownerNull) {
        memcpy(&storedReceiver, (const void *)(ownerX20 + 0x18), sizeof(storedReceiver));
    }
    if (storedReceiver == 0) __sync_add_and_fetch(&g_nilStoredReceiver, 1);
    if (providerX22 == 0) __sync_add_and_fetch(&g_nilProviderRegister, 1);
    BOOL regsMatchArray = (wifiX24 == firstPtr && mobileX23 == secondPtr);
    if (!regsMatchArray) __sync_add_and_fetch(&g_snapshotMismatches, 1);

    if (callNumber <= 8 || needsFallback) {
        ProbeRecord([NSString stringWithFormat:
            @"EXACT CALL #%llu count=2 owner[x20]=%p storedReceiver[x20+0x18]=%p provider[x22]=%p wifi[x24]=%p mobile[x23]=%p array[0]=%p array[1]=%p regMatches=%@ action=%@",
            (unsigned long long)callNumber,
            (void *)ownerX20, (void *)storedReceiver, (void *)providerX22,
            (void *)wifiX24, (void *)mobileX23,
            (void *)firstPtr, (void *)secondPtr,
            regsMatchArray ? @"yes" : @"no",
            needsFallback ? @"EMPTY_ARRAY_FALLBACK" : @"ORIGINAL_ARRAY"], YES);
    }

    if (needsFallback) return g_origArray(receiver, selector, NULL, 0);
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
        method_setImplementation(arrayMethod, (IMP)ProbeArrayEntry);
    }
    ProbeRecord([NSString stringWithFormat:@"Probe installed: %u getter implementations; NSArray hook=%@; YouTube slide=0x%llx",
                 g_hookCount, arrayMethod ? @"yes" : @"no",
                 (unsigned long long)_dyld_get_image_vmaddr_slide(0)], NO);
}

__attribute__((constructor)) static void ProbeInitialize(void) {
    dispatch_async(dispatch_get_main_queue(), ^{ ProbeInstall(); });
}
