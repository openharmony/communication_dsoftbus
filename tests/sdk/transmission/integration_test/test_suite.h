#ifndef ECHO_TEST_SUITE_H
#define ECHO_TEST_SUITE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <memory.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

#define LOG(FMT, args...) printf(FMT "\n", ##args)

#define ECHO_SERVICE_PKGNAME      "dms"
#define ECHO_SERVICE_SESSION_NAME "ohos.distributedschedule.dms.echo"
#define ECHO_SERVICE_CONSUMER_SESSION_NAME "ohos.distributedschedule.dms.echo"

typedef int (*SendMethod)(int sessionId, const void *data, unsigned int len);

inline time_t GetCurrent(void)
{
    struct timespec time;
    int ret = clock_gettime(CLOCK_MONOTONIC, &time);
    if(ret != 0){
        LOG("%s: get time failed!", __func__);
    }
    return time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static inline int32_t ExecWithRetry(int sessionId, const void *data, unsigned int len, SendMethod method, time_t *sendTime) {
    uint8_t retryTimes = 5; 
    int32_t ret = -999;
    while(retryTimes-- > 0 && ret == -999) {
        if(sendTime != NULL) {
            *sendTime = GetCurrent();
        }
        ret = method(sessionId, data, len);
        if(ret == 0) {
            break;
        }
    }
    return ret;
}

#endif