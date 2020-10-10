#if __APPLE__
    #include <TargetConditionals.h>
    #if TARGET_OS_IPHONE
        #include <asl.h>
        // #include <os/proc.h>
    #endif
#endif
