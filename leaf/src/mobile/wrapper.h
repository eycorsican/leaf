#if __APPLE__
    #include <TargetConditionals.h>
    #include <asl.h>
#elif __ANDROID__
    #include <android/log.h>
#endif
