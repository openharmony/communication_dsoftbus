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

#include "nstackx_device_local.h"
#include <securec.h>
#include "nstackx_dfinder_hidump.h"
#include "nstackx_error.h"
#include "nstackx_dev.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_statistics.h"
#include "nstackx_timer.h"
#include "nstackx_util.h"
#include "nstackx_device_remote.h"
#include "nstackx_list.h"

#define TAG "LOCALDEVICE"
enum {
    IFACE_STATE_READY,
    IFACE_STATE_DESTROYING,
    IFACE_STATE_CREATING,
};

struct LocalIface {
    List node;

    char ifname[NSTACKX_MAX_INTERFACE_NAME_LEN];
    char ipStr[NSTACKX_MAX_IP_STRING_LEN];
    struct in_addr ip;

    uint8_t type;
    uint8_t state;
    uint8_t createCount;
    struct timespec updateTime;

    Timer *timer;
    CoapCtxType *ctx;
};

typedef struct LocalDevice_ {
    DeviceInfo deviceInfo;

    List readyList[IFACE_TYPE_MAX];
    List creatingList;
    List destroyList;

    Timer *timer;
    bool inited;
} LocalDevice;

static LocalDevice g_localDevice;

#define LOCAL_DEVICE_OFFLINE_DEFERRED_DURATION 5000 /* Defer local device offline event, 5 seconds */

#define NSTACKX_DEFAULT_DEVICE_NAME "nStack Device"

#define IFACE_COAP_CTX_INIT_MAX_RETRY_TIMES 4
static const uint32_t g_ifaceCoapCtxRetryBackoffList[IFACE_COAP_CTX_INIT_MAX_RETRY_TIMES] = { 10, 15, 25, 100 };

static pthread_mutex_t g_capabilityLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_serviceDataLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_businessDataLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_extendServiceDataLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_deviceInfoLock = PTHREAD_MUTEX_INITIALIZER;

static void LocalDeviceTimeout(void *data)
{
    (void)data;

    struct timespec cur;
    ClockGetTime(CLOCK_MONOTONIC, &cur);

    uint32_t nextTimeout = 0;
    List *pos = NULL;
    List *tmp = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &g_localDevice.destroyList) {
        struct LocalIface *iface = (struct LocalIface *)pos;
        uint32_t diff = GetTimeDiffMs(&cur, &iface->updateTime);
        if (diff < LOCAL_DEVICE_OFFLINE_DEFERRED_DURATION) {
            nextTimeout = LOCAL_DEVICE_OFFLINE_DEFERRED_DURATION - diff;
            break;
        }

        DestroyLocalIface(iface, NSTACKX_FALSE);
    }

    if (nextTimeout != 0) {
        DFINDER_LOGD(TAG, "start offline timer again, timeout %u", nextTimeout);
        (void)TimerSetTimeout(g_localDevice.timer, nextTimeout, NSTACKX_FALSE);
    }
}

void LocalDeviceDeinit(void)
{
    if (!g_localDevice.inited) {
        DFINDER_LOGW(TAG, "local device not inited");
        return;
    }

    List *pos = NULL;
    List *tmp = NULL;
    int i;
    for (i = 0; i < IFACE_TYPE_MAX; i++) {
        LIST_FOR_EACH_SAFE(pos, tmp, &g_localDevice.readyList[i]) {
            DestroyLocalIface((struct LocalIface *)pos, NSTACKX_TRUE);
        }
    }

    LIST_FOR_EACH_SAFE(pos, tmp, &g_localDevice.destroyList) {
        DestroyLocalIface((struct LocalIface *)pos, NSTACKX_TRUE);
    }

    LIST_FOR_EACH_SAFE(pos, tmp, &g_localDevice.creatingList) {
        DestroyLocalIface((struct LocalIface *)pos, NSTACKX_TRUE);
    }

    if (g_localDevice.timer != NULL) {
        TimerDelete(g_localDevice.timer);
        g_localDevice.timer = NULL;
    }

    g_localDevice.inited = NSTACKX_FALSE;
}

int LocalDeviceInit(EpollDesc epollfd)
{
    (void)memset_s(&g_localDevice, sizeof(g_localDevice), 0, sizeof(g_localDevice));
    g_localDevice.timer = TimerStart(epollfd, 0, NSTACKX_FALSE, LocalDeviceTimeout, NULL);
    if (g_localDevice.timer == NULL) {
        DFINDER_LOGE(TAG, "timer init failed");
        return NSTACKX_EFAILED;
    }

    int i;
    for (i = 0; i < IFACE_TYPE_MAX; i++) {
        ListInitHead(&g_localDevice.readyList[i]);
    }

    ListInitHead(&g_localDevice.destroyList);
    ListInitHead(&g_localDevice.creatingList);
    g_localDevice.inited = NSTACKX_TRUE;

    return NSTACKX_EOK;
}

void ResetLocalDeviceTaskCount(uint8_t isBusy)
{
    if (g_localDevice.timer != NULL) {
        if (isBusy) {
            DFINDER_LOGI(TAG, "in this busy interval: offline deferred timer task count %llu",
                         g_localDevice.timer->task.count);
        }
        g_localDevice.timer->task.count = 0;
    }
}

static inline void LocalIfaceChangeState(struct LocalIface *iface, List *targetList, uint8_t state)
{
    DFINDER_LOGI(TAG, "iface %s state change: %hhu -> %hhu", iface->ifname, iface->state, state);
    ListRemoveNode(&iface->node);
    iface->state = state;
    ListInsertTail(targetList, &iface->node);
}

static void LocalIfaceCreateContextTimeout(void *arg)
{
    struct LocalIface *iface = (struct LocalIface *)arg;
    DFINDER_LOGD(TAG, "iface %s create context for %u times", iface->ifname, iface->createCount);
    iface->ctx = CoapServerInit(&iface->ip, (void *)iface);
    if (iface->ctx != NULL) {
        DFINDER_LOGD(TAG, "iface %s create coap context success", iface->ifname);
        TimerDelete(iface->timer);
        iface->timer = NULL;
        LocalIfaceChangeState(iface, &g_localDevice.readyList[iface->type], IFACE_STATE_READY);
        return;
    }

    if (iface->createCount >= IFACE_COAP_CTX_INIT_MAX_RETRY_TIMES) {
        DFINDER_LOGE(TAG, "create context retry reach max times %hhu", iface->createCount);
        DestroyLocalIface(iface, NSTACKX_FALSE);
        return;
    }

    (void)TimerSetTimeout(iface->timer, g_ifaceCoapCtxRetryBackoffList[iface->createCount], NSTACKX_FALSE);
    iface->createCount++;
}

static inline bool NeedCreateSynchronously(uint8_t ifaceType)
{
    return ifaceType < IFACE_TYPE_P2P;
}

static int LocalIfaceInit(struct LocalIface *iface, const char *ifname, const struct in_addr *ip, const char *ipStr)
{
    DFINDER_LOGI(TAG, "trying to bring up interface %s", ifname);

    if (strcpy_s(iface->ifname, sizeof(iface->ifname), ifname) != EOK) {
        DFINDER_LOGE(TAG, "copy ifname %s failed", ifname);
        return NSTACKX_EFAILED;
    }
    if (strcpy_s(iface->ipStr, sizeof(iface->ipStr), ipStr) != EOK) {
        DFINDER_LOGE(TAG, "copy ip string failed");
        return NSTACKX_EFAILED;
    }
    iface->type = GetIfaceType(ifname);
    iface->ip.s_addr = ip->s_addr;

    if (NeedCreateSynchronously(iface->type)) {
        iface->ctx = CoapServerInit(ip, (void *)iface);
        if (iface->ctx == NULL) {
            DFINDER_LOGE(TAG, "create coap context failed");
            IncStatistics(STATS_CREATE_SERVER_FAILED);
            return NSTACKX_EFAILED;
        }
        iface->state = IFACE_STATE_READY;
        ListInsertTail(&g_localDevice.readyList[iface->type], &iface->node);
    } else {
        iface->timer = TimerStart(GetEpollFD(), g_ifaceCoapCtxRetryBackoffList[0],
            NSTACKX_FALSE, LocalIfaceCreateContextTimeout, iface);
        if (iface->timer == NULL) {
            DFINDER_LOGE(TAG, "iface %s create timer to create context async failed", iface->ifname);
            return NSTACKX_EFAILED;
        }
        iface->createCount = 1;
        iface->state = IFACE_STATE_CREATING;
        ListInsertTail(&g_localDevice.creatingList, &iface->node);
    }

    return NSTACKX_EOK;
}

static struct LocalIface *CreateLocalIface(const char *ifname, const struct in_addr *ip, const char *ipStr)
{
    struct LocalIface *iface = calloc(1, sizeof(struct LocalIface));
    if (iface == NULL) {
        DFINDER_LOGE(TAG, "alloc falied");
        return NULL;
    }

    if (LocalIfaceInit(iface, ifname, ip, ipStr) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "local iface init failed");
        free(iface);
        return NULL;
    }

    return iface;
}

void DestroyLocalIface(struct LocalIface *iface, bool moduleDeinit)
{
    DFINDER_LOGI(TAG, "destroy iface %s, type: %hhu state: %hhu", iface->ifname, iface->type, iface->state);

#ifdef DFINDER_SAVE_DEVICE_LIST
    DestroyRxIfaceByIfname(iface->ifname);
#endif

    if (iface->ctx != NULL) {
        CoapServerDestroy(iface->ctx, moduleDeinit);
    }
    ListRemoveNode(&iface->node);
    if (iface->timer != NULL) {
        TimerDelete(iface->timer);
    }
    free(iface);
}

static struct LocalIface *GetLocalIface(List *head, const char *ifname, const struct in_addr *ip)
{
    List *pos = NULL;
    LIST_FOR_EACH(pos, head) {
        struct LocalIface *iface = (struct LocalIface *)pos;
        DFINDER_LOGD(TAG, "local ifname: %s, ifname: %s", iface->ifname, ifname);
        if (strcmp(iface->ifname, ifname) == 0 && (ip == NULL || ip->s_addr == iface->ip.s_addr)) {
            return iface;
        }
    }

    return NULL;
}

static struct LocalIface *GetActiveLocalIface(const char *ifname)
{
    uint8_t type = GetIfaceType(ifname);
    struct LocalIface *iface = GetLocalIface(&g_localDevice.readyList[type], ifname, NULL);
    if (iface == NULL) {
        iface = GetLocalIface(&g_localDevice.creatingList, ifname, NULL);
    }

    return iface;
}

static void AddToDestroyList(struct LocalIface *iface)
{
    if (iface->state != IFACE_STATE_DESTROYING) {
        if (ListIsEmpty(&g_localDevice.destroyList)) {
            (void)TimerSetTimeout(g_localDevice.timer, LOCAL_DEVICE_OFFLINE_DEFERRED_DURATION, NSTACKX_FALSE);
            DFINDER_LOGD(TAG, "iface %s start offline timer", iface->ifname);
        }
        LocalIfaceChangeState(iface, &g_localDevice.destroyList, IFACE_STATE_DESTROYING);
        ClockGetTime(CLOCK_MONOTONIC, &iface->updateTime);
        if (iface->timer != NULL) {
            (void)TimerSetTimeout(iface->timer, 0, NSTACKX_FALSE);
            iface->createCount = 0;
        }
    }
}

int AddLocalIface(const char *ifname, const struct in_addr *ip)
{
    struct LocalIface *iface = GetActiveLocalIface(ifname);
    if (iface == NULL) {
        iface = GetLocalIface(&g_localDevice.destroyList, ifname, ip);
        if (iface != NULL) {
            DFINDER_LOGW(TAG, "iface %s is in destroying", ifname);
            LocalIfaceChangeState(iface, &g_localDevice.readyList[iface->type], IFACE_STATE_READY);
            return NSTACKX_EOK;
        }
    } else {
        if (iface->ip.s_addr == ip->s_addr) {
            DFINDER_LOGW(TAG, "iface %s already existed", ifname);
            return NSTACKX_EOK;
        }

        AddToDestroyList(iface);
    }

    char ipStr[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, ip, ipStr, sizeof(ipStr)) == NULL) {
        DFINDER_LOGE(TAG, "ip to string failed");
        return NSTACKX_EFAILED;
    }

    iface = CreateLocalIface(ifname, ip, ipStr);
    return (iface == NULL) ? NSTACKX_EFAILED : NSTACKX_EOK;
}

void RemoveLocalIface(const char *ifname)
{
    struct LocalIface *iface = GetActiveLocalIface(ifname);
    if (iface == NULL) {
        DFINDER_LOGW(TAG, "iface %s not found when deleting iface", ifname);
        return;
    }

    AddToDestroyList(iface);
}

static void RemoveAllLocalIfaceOfList(List *list)
{
    List *pos = NULL;
    List *tmp = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, list) {
        AddToDestroyList((struct LocalIface *)pos);
    }
}

static void RemoveAllLocalIface(void)
{
    uint8_t i;
    for (i = IFACE_TYPE_ETH; i < IFACE_TYPE_MAX; i++) {
        RemoveAllLocalIfaceOfList(&g_localDevice.readyList[i]);
    }

    RemoveAllLocalIfaceOfList(&g_localDevice.creatingList);
}

static inline void RemoveSpecifiedLocalIface(const NSTACKX_InterfaceInfo *ifInfo, uint32_t ifNums)
{
    uint32_t i;
    for (i = 0; i < ifNums; ++i) {
        RemoveLocalIface(ifInfo[i].networkName);
    }
}

static int AddLocalIfaceIpChanged(const NSTACKX_InterfaceInfo *ifInfo, uint32_t ifNums)
{
    uint8_t ifaceType = IFACE_TYPE_MAX;
    uint32_t i;
    for (i = 0; i < ifNums; ++i) {
        if (ifInfo->networkName[0] == '\0' || ifInfo->networkIpAddr[0] == '\0') {
            DFINDER_LOGI(TAG, "skip empty network name or ip addr");
            continue;
        }

        struct in_addr ip;
        if (inet_pton(AF_INET, ifInfo[i].networkIpAddr, &ip) != 1) {
            DFINDER_LOGE(TAG, "invalid ip addr of iface %u", ifInfo[i].networkName);
            return NSTACKX_EFAILED;
        }

        if (ip.s_addr == 0) {
            DFINDER_LOGI(TAG, "skip ip with any");
            continue;
        }

        if (AddLocalIface(ifInfo[i].networkName, &ip) != NSTACKX_EOK) {
            DFINDER_LOGE(TAG, "create local iface %s failed", ifInfo[i].networkName);
            return NSTACKX_EFAILED;
        }

        uint8_t curIfaceType = GetIfaceType(ifInfo[i].networkName);
        if (curIfaceType < ifaceType) { /* storge the highest priority interface name */
            if (strcpy_s(g_localDevice.deviceInfo.networkName, sizeof(g_localDevice.deviceInfo.networkName),
                ifInfo[i].networkName) != EOK) {
                DFINDER_LOGE(TAG, "copy ifname %s failed", ifInfo[i].networkName);
                return NSTACKX_EFAILED;
            }
            ifaceType = curIfaceType;
        }
    }

    return NSTACKX_EOK;
}

static int CopyDeviceInfoV2(const NSTACKX_LocalDeviceInfoV2 *devInfo)
{
    if (strcpy_s(g_localDevice.deviceInfo.deviceId, sizeof(g_localDevice.deviceInfo.deviceId),
        devInfo->deviceId) != EOK) {
        DFINDER_LOGE(TAG, "copy device id failed");
        return NSTACKX_EFAILED;
    }

    if (devInfo->name[0] == '\0') {
        DFINDER_LOGW(TAG, "Invalid device name. Will use default name");
        (void)strcpy_s(g_localDevice.deviceInfo.deviceName,
            sizeof(g_localDevice.deviceInfo.deviceName), NSTACKX_DEFAULT_DEVICE_NAME);
    } else {
        if (strcpy_s(g_localDevice.deviceInfo.deviceName,
            sizeof(g_localDevice.deviceInfo.deviceName), devInfo->name) != EOK) {
            DFINDER_LOGE(TAG, "copy device name %s failed", devInfo->name);
            return NSTACKX_EFAILED;
        }
    }

    g_localDevice.deviceInfo.deviceType = devInfo->deviceType;
    g_localDevice.deviceInfo.businessType = devInfo->businessType;
    if (devInfo->hasDeviceHash) {
        SetLocalDeviceHash(devInfo->deviceHash);
    }

    return NSTACKX_EOK;
}

int RegisterLocalDeviceV2(const NSTACKX_LocalDeviceInfoV2 *devInfo, int registerType)
{
    if (PthreadMutexLock(&g_deviceInfoLock) != 0) {
        DFINDER_LOGE(TAG, "failed to lock");
        return NSTACKX_EFAILED;
    }
    if (registerType == REGISTER_TYPE_UPDATE_ALL) {
        RemoveAllLocalIface();
    } else {
        RemoveSpecifiedLocalIface(devInfo->localIfInfo, devInfo->ifNums);
    }

    if (CopyDeviceInfoV2(devInfo) != NSTACKX_EOK) {
        if (PthreadMutexUnlock(&g_deviceInfoLock) != 0) {
            DFINDER_LOGE(TAG, "failed to unlock");
        }
        return NSTACKX_EFAILED;
    }

    if (AddLocalIfaceIpChanged(devInfo->localIfInfo, devInfo->ifNums) != NSTACKX_EOK) {
        if (registerType == REGISTER_TYPE_UPDATE_ALL) {
            RemoveAllLocalIface(); /* maybe some ifaces is added, so remove all ifaces again */
        }
        if (PthreadMutexUnlock(&g_deviceInfoLock) != 0) {
            DFINDER_LOGE(TAG, "failed to unlock");
        }
        return NSTACKX_EFAILED;
    }
    if (PthreadMutexUnlock(&g_deviceInfoLock) != 0) {
        DFINDER_LOGE(TAG, "failed to unlock");
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

void ConfigureLocalDeviceName(const char *localDeviceName)
{
    char backupDevName[NSTACKX_MAX_DEVICE_NAME_LEN] = {0};
    if (memcpy_s(backupDevName, sizeof(backupDevName), g_localDevice.deviceInfo.deviceName,
        sizeof(g_localDevice.deviceInfo.deviceName)) != EOK) {
        DFINDER_LOGE(TAG, "backup local device name failed!");
        return;
    }
    if (strncpy_s(g_localDevice.deviceInfo.deviceName, NSTACKX_MAX_DEVICE_NAME_LEN,
        localDeviceName, NSTACKX_MAX_DEVICE_NAME_LEN - 1) != EOK) {
        DFINDER_LOGW(TAG, "copy local device failed, will use current name");
        if (strcpy_s(g_localDevice.deviceInfo.deviceName, NSTACKX_MAX_DEVICE_NAME_LEN, backupDevName) != EOK) {
            DFINDER_LOGE(TAG, "config device name failed and cannot restore!");
        }
    }
}

void SetLocalDeviceHash(uint64_t deviceHash)
{
    (void)memset_s(g_localDevice.deviceInfo.deviceHash, sizeof(g_localDevice.deviceInfo.deviceHash),
        0, sizeof(g_localDevice.deviceInfo.deviceHash));
    if (sprintf_s(g_localDevice.deviceInfo.deviceHash, DEVICE_HASH_LEN,
        "%ju", deviceHash) == -1) {
        DFINDER_LOGE(TAG, "set device hash error");
    }
}

int SetLocalDeviceCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    if (PthreadMutexLock(&g_capabilityLock) != 0) {
        DFINDER_LOGE(TAG, "failed to lock");
        return NSTACKX_EFAILED;
    }
    (void)memset_s(g_localDevice.deviceInfo.capabilityBitmap, sizeof(g_localDevice.deviceInfo.capabilityBitmap),
        0, sizeof(g_localDevice.deviceInfo.capabilityBitmap));
    g_localDevice.deviceInfo.capabilityBitmapNum = 0;

    if (capabilityBitmapNum > 0) {
        if (memcpy_s(g_localDevice.deviceInfo.capabilityBitmap, sizeof(g_localDevice.deviceInfo.capabilityBitmap),
            capabilityBitmap, sizeof(uint32_t) * capabilityBitmapNum) != EOK) {
            DFINDER_LOGE(TAG, "capabilityBitmap copy error");
            if (PthreadMutexUnlock(&g_capabilityLock) != 0) {
                DFINDER_LOGE(TAG, "failed to unlock");
            }
            return NSTACKX_EFAILED;
        }
    }

    g_localDevice.deviceInfo.capabilityBitmapNum = capabilityBitmapNum;
    if (PthreadMutexUnlock(&g_capabilityLock) != 0) {
        DFINDER_LOGE(TAG, "failed to unlock");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t SetLocalDeviceServiceData(const char *serviceData)
{
    if (PthreadMutexLock(&g_serviceDataLock) != 0) {
        DFINDER_LOGE(TAG, "failed to lock");
        return NSTACKX_EFAILED;
    }
    if (strcpy_s(g_localDevice.deviceInfo.serviceData, NSTACKX_MAX_SERVICE_DATA_LEN, serviceData) != EOK) {
        DFINDER_LOGE(TAG, "serviceData copy error");
        if (PthreadMutexUnlock(&g_serviceDataLock) != 0) {
            DFINDER_LOGE(TAG, "failed to unlock");
        }
        return NSTACKX_EFAILED;
    }
    if (PthreadMutexUnlock(&g_serviceDataLock) != 0) {
        DFINDER_LOGE(TAG, "failed to unlock");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

void SetLocalDeviceBusinessType(uint8_t businessType)
{
    g_localDevice.deviceInfo.businessType = businessType;
}

uint8_t GetLocalDeviceBusinessType(void)
{
    return g_localDevice.deviceInfo.businessType;
}

int SetLocalDeviceBusinessData(const char *data, bool unicast)
{
    if (PthreadMutexLock(&g_businessDataLock) != 0) {
        DFINDER_LOGE(TAG, "failed to lock");
        return NSTACKX_EFAILED;
    }
    int ret = EOK;
    if (unicast) {
        ret = strcpy_s(g_localDevice.deviceInfo.businessData.businessDataUnicast,
            NSTACKX_MAX_BUSINESS_DATA_LEN, data);
    } else {
        ret = strcpy_s(g_localDevice.deviceInfo.businessData.businessDataBroadcast,
            NSTACKX_MAX_BUSINESS_DATA_LEN, data);
    }

    if (ret != EOK) {
        DFINDER_LOGE(TAG, "businessData copy error, unicast: %d", unicast);
        if (PthreadMutexUnlock(&g_businessDataLock) != 0) {
            DFINDER_LOGE(TAG, "failed to unlock");
        }
        return NSTACKX_EFAILED;
    }

    if (PthreadMutexUnlock(&g_businessDataLock) != 0) {
        DFINDER_LOGE(TAG, "failed to unlock");
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

int32_t LocalizeNotificationMsg(const char *msg)
{
    if (strcpy_s(g_localDevice.deviceInfo.notification, NSTACKX_MAX_NOTIFICATION_DATA_LEN, msg) != EOK) {
        DFINDER_LOGE(TAG, "copy notification msg to local dev failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

uint8_t GetLocalDeviceMode(void)
{
    return g_localDevice.deviceInfo.mode;
}

void SetLocalDeviceMode(uint8_t mode)
{
    g_localDevice.deviceInfo.mode = mode;
}

#ifndef DFINDER_USE_MINI_NSTACKX
int32_t SetLocalDeviceExtendServiceData(const char *extendServiceData)
{
    if (PthreadMutexLock(&g_extendServiceDataLock) != 0) {
        DFINDER_LOGE(TAG, "failed to lock");
        return NSTACKX_EFAILED;
    }
    if (strcpy_s(g_localDevice.deviceInfo.extendServiceData, NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN,
        extendServiceData) != EOK) {
        DFINDER_LOGE(TAG, "extendServiceData copy error");
        if (PthreadMutexUnlock(&g_extendServiceDataLock) != 0) {
            DFINDER_LOGE(TAG, "failed to unlock");
        }
        return NSTACKX_EFAILED;
    }
    if (PthreadMutexUnlock(&g_extendServiceDataLock) != 0) {
        DFINDER_LOGE(TAG, "failed to unlock");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

#ifndef _WIN32
void DetectLocalIface(void *arg)
{
    struct ifconf ifc;
    struct ifreq req[INTERFACE_MAX];
    int fd = GetInterfaceList(&ifc, req, sizeof(req));
    if (fd < 0) {
        DFINDER_LOGE(TAG, "get iface list failed");
        return;
    }

    int interfaceNum = ifc.ifc_len / (int)sizeof(struct ifreq);
    for (int i = 0; i < interfaceNum && i < INTERFACE_MAX; i++) {
        /* get IP of this interface */
        int state = GetInterfaceIP(fd, &req[i]);
        if (state == NSTACKX_EFAILED) {
            (void)close(fd);
            return;
        } else if (state == NSTACKX_EINVAL) {
            continue;
        }

        uint8_t ifaceType = GetIfaceType(req[i].ifr_name);
        if (ifaceType > IFACE_TYPE_WLAN) {
            DFINDER_LOGI(TAG, "skip iface %s", req[i].ifr_name);
            continue;
        }

        struct in_addr *ip = &((struct sockaddr_in *)&req[i].ifr_addr)->sin_addr;
        if (req[i].ifr_addr.sa_family != AF_INET || ip->s_addr == 0) {
            DFINDER_LOGD(TAG, "iface %s is not ipv4 or ip is any", req[i].ifr_name);
            continue;
        }

        DFINDER_LOGI(TAG, "try to add new iface %s", req[i].ifr_name);
        (void)AddLocalIface(req[i].ifr_name, ip);
    }
    (void)close(fd);

    (void)arg;
}
#endif /* _WIN32 */

#endif /* END OF DFINDER_USE_MINI_NSTACKX */

int GetBroadcastIp(const struct LocalIface *iface, char *ipStr, size_t ipStrLen)
{
#ifdef _WIN32
    return GetIfBroadcastAddr(&iface->ip, ipStr, ipStrLen);
#else
    return GetIfBroadcastIp(iface->ifname, ipStr, ipStrLen);
#endif
}

const char *GetLocalDeviceId(void)
{
    return g_localDevice.deviceInfo.deviceId;
}

DeviceInfo *GetLocalDeviceInfo(void)
{
    return &g_localDevice.deviceInfo;
}

const char *GetLocalDeviceNetworkName(void)
{
    return g_localDevice.deviceInfo.networkName;
}

const struct in_addr *GetLocalIfaceIp(const struct LocalIface *iface)
{
    return &iface->ip;
}

const char *GetLocalIfaceIpStr(const struct LocalIface *iface)
{
    return iface->ipStr;
}

const char *GetLocalIfaceName(const struct LocalIface *iface)
{
    return iface->ifname;
}

CoapCtxType *LocalIfaceGetCoapCtx(const char *ifname)
{
    int i;
    for (i = 0; i < IFACE_TYPE_MAX; i++) {
        List *pos = NULL;
        LIST_FOR_EACH(pos, &g_localDevice.readyList[i]) {
            struct LocalIface *iface = (struct LocalIface *)pos;
            if (strcmp(iface->ifname, ifname) != 0) {
                continue;
            }

            return iface->ctx;
        }
    }

    return NULL;
}

#ifdef _WIN32
static struct LocalIface *GetLocalIfaceByLocalIp(const struct in_addr *ip)
{
    int i;
    for (i = 0; i < IFACE_TYPE_MAX; i++) {
        List *pos = NULL;
        LIST_FOR_EACH(pos, &g_localDevice.readyList[i]) {
            struct LocalIface *iface = (struct LocalIface *)pos;
            if (iface->ip.s_addr != ip->s_addr) {
                continue;
            }

            return iface;
        }
    }

    return NULL;
}
#endif

#ifndef DFINDER_USE_MINI_NSTACKX
static inline bool IfaceTypeIsMatch(uint8_t ifaceType, uint8_t serverType)
{
    return serverType == INVALID_TYPE ||
        (serverType == SERVER_TYPE_WLANORETH && (ifaceType == IFACE_TYPE_ETH || ifaceType == IFACE_TYPE_WLAN)) ||
        (serverType == SERVER_TYPE_P2P && ifaceType == IFACE_TYPE_P2P) ||
        (serverType == SERVER_TYPE_USB && ifaceType == IFACE_TYPE_USB);
}

CoapCtxType *LocalIfaceGetCoapCtxByRemoteIp(const struct in_addr *remoteIp, uint8_t serverType)
{
    struct LocalIface *iface = NULL;
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = remoteIp->s_addr;
#ifdef _WIN32
    InterfaceInfo localDev;
    (void)memset_s(&localDev, sizeof(InterfaceInfo), 0, sizeof(InterfaceInfo));
    if (GetTargetAdapter(&addr, &localDev) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "get target adapter failed");
        return NULL;
    }
    struct in_addr localIp = { .s_addr = localDev.ipAddr };
    iface = GetLocalIfaceByLocalIp(&localIp);
#else
    struct ifreq req;
    (void)memset_s(&req, sizeof(struct ifreq), 0, sizeof(struct ifreq));
    if (GetTargetInterface(&addr, &req) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "get target interface failed");
        return NULL;
    }

    uint8_t ifaceType = GetIfaceType(req.ifr_ifrn.ifrn_name);
    DFINDER_LOGD(TAG, "ifaceType: %hhu", ifaceType);
    iface = GetLocalIface(&g_localDevice.readyList[ifaceType], req.ifr_ifrn.ifrn_name, NULL);
#endif
    if (iface == NULL) {
        DFINDER_LOGE(TAG, "can not find iface");
        return NULL;
    }

    if (!IfaceTypeIsMatch(iface->type, serverType)) {
        DFINDER_LOGE(TAG, "type not match, iface type: %hhu, server type: %hhu", iface->type, serverType);
        return NULL;
    }

    return iface->ctx;
}
#endif

#ifdef NSTACKX_DFINDER_HIDUMP
int LocalIfaceDump(char *buf, size_t size)
{
    List *pos = NULL;
    struct LocalIface *iface = NULL;
    int ret;
    size_t index = 0;
    int i;
    for (i = 0; i < IFACE_TYPE_MAX; i++) {
        LIST_FOR_EACH(pos, &g_localDevice.readyList[i]) {
            iface = (struct LocalIface *)pos;
            ret = DFinderDumpIface(buf + index, size - index, iface->ifname, &iface->ip, iface->state);
            if (ret < 0 || (uint32_t)ret > size - index) {
                return NSTACKX_EFAILED;
            }

            index += (uint32_t)ret;
        }
    }

    LIST_FOR_EACH(pos, &g_localDevice.creatingList) {
        iface = (struct LocalIface *)pos;
        ret = DFinderDumpIface(buf + index, size - index, iface->ifname, &iface->ip, iface->state);
        if (ret < 0 || (uint32_t)ret > size - index) {
            return NSTACKX_EFAILED;
        }

        index += (uint32_t)ret;
    }

    LIST_FOR_EACH(pos, &g_localDevice.destroyList) {
        iface = (struct LocalIface *)pos;
        ret = DFinderDumpIface(buf + index, size - index, iface->ifname, &iface->ip, iface->state);
        if (ret < 0 || (uint32_t)ret > size - index) {
            return NSTACKX_EFAILED;
        }

        index += (uint32_t)ret;
    }

    return index;
}
#endif
