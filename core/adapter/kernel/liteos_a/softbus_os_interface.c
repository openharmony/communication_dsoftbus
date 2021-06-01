/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "softbus_os_interface.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "securec.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define MS_PER_SECOND 1000
#define US_PER_MSECOND 1000

static unsigned int g_timerType;

void *SoftBusCreateTimer(void **timerId, void *timerFunc, unsigned int type)
{
    if (timerId == NULL) {
        LOG_ERR("timerId is null");
        return NULL;
    }
    struct sigevent envent;
    (void)memset_s(&envent, sizeof(envent), 0, sizeof(envent));
    envent.sigev_notify = SIGEV_SIGNAL;
    envent.sigev_signo = SIGUSR1;
    signal(SIGUSR1, timerFunc);

    g_timerType = type;
    if (timer_create(CLOCK_REALTIME, &envent, timerId) != 0) {
        LOG_ERR("timer create error, errno code: [%d]", errno);
        return NULL;
    }

    return *timerId;
}

int SoftBusStartTimer(void *timerId, unsigned int tickets)
{
    if (timerId == NULL) {
        LOG_ERR("timerId is null");
        return SOFTBUS_ERR;
    }

    struct itimerspec value;
    (void)memset_s(&value, sizeof(value), 0, sizeof(value));
    value.it_value.tv_sec = tickets / MS_PER_SECOND;
    value.it_value.tv_nsec = 0;
    if (g_timerType == TIMER_TYPE_ONCE) {
        value.it_interval.tv_sec = tickets = 0;
        value.it_interval.tv_nsec = 0;
    } else {
        value.it_interval.tv_sec = tickets / MS_PER_SECOND;
        value.it_interval.tv_nsec = 0;
    }

    if (timer_settime(timerId, 0, &value, NULL) != 0) {
        LOG_ERR("timer start error, errno code: [%d]", errno);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int SoftBusDeleteTimer(void *timerId)
{
    if (timerId == NULL) {
        LOG_ERR("timerId is null");
        return SOFTBUS_ERR;
    }

    if (timer_delete(timerId) != 0) {
        LOG_ERR("timer delete err, errno code: [%d]", errno);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int SoftBusSleepMs(unsigned int ms)
{
    int ret;
    struct timeval tm;
    tm.tv_sec = ms / MS_PER_SECOND;
    tm.tv_usec = (ms % MS_PER_SECOND) * US_PER_MSECOND;

    do {
        ret = select(0, NULL, NULL, NULL, &tm);
    } while ((ret == -1) && (errno == EINTR));

    return SOFTBUS_ERR;
}

int SoftBusReadFile(const char *fileName, char *readBuf, int maxLen)
{
    if (fileName == NULL || readBuf == NULL || maxLen <= 0) {
        return SOFTBUS_FILE_ERR;
    }

    int fd = open(fileName, O_RDONLY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        LOG_ERR("ReadFile get deviceid open file fail");
        return SOFTBUS_FILE_ERR;
    }
    int fileLen = lseek(fd, 0, SEEK_END);
    if (fileLen <= 0 || fileLen > maxLen) {
        LOG_ERR("ReadFile maxLen failed or over maxLen");
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    int ret = lseek(fd, 0, SEEK_SET);
    if (ret < 0) {
        LOG_ERR("ReadFile get deviceid lseek file fail");
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    ret = read(fd, readBuf, fileLen);
    if (ret < 0) {
        LOG_ERR("ReadFile read deviceid fail, ret=%d", ret);
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}

int SoftBusWriteFile(const char *fileName, const char *writeBuf, int len)
{
    if (fileName == NULL || writeBuf == NULL || len <= 0) {
        return SOFTBUS_FILE_ERR;
    }

    int ret;
    int fd;

    fd = open(fileName, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        LOG_ERR("WriteDeviceId open file fail");
        return SOFTBUS_FILE_ERR;
    }
    ret = write(fd, writeBuf, len);
    if (ret != len) {
        LOG_ERR("WriteDeviceId write fail");
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}