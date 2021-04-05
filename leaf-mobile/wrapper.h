#if __APPLE__
    #include <TargetConditionals.h>
    #if TARGET_OS_IPHONE
        #include <asl.h>
        // #include <os/proc.h>
    #elif TARGET_OS_OSX
        #include <asl.h>
    #endif
#elif __ANDROID__
    #include <android/log.h>
#endif
