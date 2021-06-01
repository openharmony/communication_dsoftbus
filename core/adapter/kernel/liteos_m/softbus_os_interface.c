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

#include "cmsis_os2.h"
#include "securec.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "utils_file.h"

#define MS_PER_SECOND 1000

void *SoftBusCreateTimer(void **timerId, void *timerFunc, unsigned int type)
{
    (void)timerId;

    void *id = osTimerNew((osTimerFunc_t)timerFunc, type, NULL, NULL);
    if (id != NULL) {
        LOG_INFO("create timer success");
        return id;
    }
    LOG_ERR("create timer failed");
    return NULL;
}

int SoftBusStartTimer(void *timerId, unsigned int ms)
{
    if (osTimerStart(timerId, ms * osKernelGetTickFreq() / MS_PER_SECOND) != osOK) {
        LOG_ERR("start timer failed");
        (void)osTimerDelete(timerId);
        return SOFTBUS_ERR;
    }

    LOG_INFO("start timer success");
    return SOFTBUS_OK;
}

int SoftBusDeleteTimer(void *timerId)
{
    if (osTimerDelete(timerId) != osOK) {
        LOG_ERR("delete timer failed");
        return SOFTBUS_ERR;
    }

    LOG_INFO("delete timer success");
    return SOFTBUS_OK;
}

int SoftBusSleepMs(unsigned int ms)
{
    osDelay(ms * osKernelGetTickFreq() / MS_PER_SECOND);
    return SOFTBUS_OK;
}

int SoftBusReadFile(const char *fileName, char *readBuf, int maxLen)
{
    if (fileName == NULL || readBuf == NULL || maxLen <= 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t fileLen = 0;
    int fd = UtilsFileOpen(fileName, O_RDONLY_FS, 0);
    if (fd < 0) {
        LOG_ERR("Read UtilsFileOpen fail");
        return SOFTBUS_FILE_ERR;
    }
    int ret = UtilsFileStat(fileName, &fileLen);
    if (ret < 0) {
        UtilsFileClose(fd);
        goto EXIT;
    }
    ret = UtilsFileSeek(fd, 0, SEEK_SET_FS);
    if (ret < 0) {
        LOG_ERR("Read UtilsFileSeek fail");
        goto EXIT;
    }
    if (fileLen > maxLen) {
        LOG_ERR("Read file len not legal, clear buf");
        goto EXIT;
    }
    ret = UtilsFileRead(fd, readBuf, maxLen);
    if (ret < 0) {
        LOG_ERR("Read UtilsFileRead, ret=%d", ret);
        goto EXIT;
    }
    UtilsFileClose(fd);
    return SOFTBUS_OK;

EXIT:
    UtilsFileClose(fd);
    return SOFTBUS_FILE_ERR;
}

int SoftBusWriteFile(const char *fileName, const char *writeBuf, int len)
{
    int ret;
    int fd;
    fd = UtilsFileOpen(fileName, O_RDWR_FS | O_CREAT_FS | O_TRUNC_FS, 0);
    if (fd < 0) {
        LOG_ERR("WriteDeviceId UtilsFileOpen fail");
        return SOFTBUS_FILE_ERR;
    }
    ret = UtilsFileWrite(fd, writeBuf, len);
    if (ret != len) {
        LOG_ERR("UtilsFileOpen UtilsFileWrite fail");
        UtilsFileClose(fd);
        return SOFTBUS_FILE_ERR;
    }
    UtilsFileClose(fd);
    return SOFTBUS_OK;
}
