/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NSTACK_COMMON_H
#define NSTACK_COMMON_H
#include "nstackx.h"
#include "nstackx_list.h"
#include "nstackx_epoll.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DFINDER_SAVE_DEVICE_LIST
typedef struct {
    NSTACKX_DeviceInfo *deviceList;
    uint32_t *deviceCountPtr;
    sem_t wait;
} GetDeviceListMessage;
#endif

struct DeviceInfo;

#ifdef DFINDER_SUPPORT_COVERITY_TAINTED_SET
void Coverity_Tainted_Set(void *buf);
#else
#define Coverity_Tainted_Set(param)
#endif

bool GetIsNotifyPerDevice(void);
void NotifyDeviceListChanged(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount);
void NotifyDeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount);
void NotificationReceived(const NSTACKX_NotificationConfig *notification);

#ifndef DFINDER_USE_MINI_NSTACKX
void NotifyMsgReceived(const char *moduleName, const char *deviceId, const uint8_t *data,
    uint32_t len, const char *srcIp);
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
void NotifyDFinderMsgRecver(DFinderMsgType msgType);
EpollDesc GetMainLoopEpollFd(void);
List *GetMainLoopEvendChain(void);
uint32_t GetDefaultDiscoverInterval(uint32_t discoverCount);
int32_t ShouldAutoReplyUnicast(uint8_t businessType);
int32_t GetServiceDiscoverInfo(const uint8_t *buf, size_t size, struct DeviceInfo *deviceInfo, char **remoteUrlPtr);
int32_t GetServiceNotificationInfo(const uint8_t *buf, size_t size, NSTACKX_NotificationConfig *notification);
List *GetEventNodeChain(void);
EpollDesc GetEpollFD(void);

static inline bool StringHasEOF(const char *str, size_t len)
{
    ssize_t i;
    for (i = (ssize_t)len - 1; i >= 0; i--) {
        if (str[i] == '\0') {
            return true;
        }
    }

    return false;
}

#ifdef __cplusplus
};
#endif

#endif /* #ifndef NSTACK_COMMON_H */
