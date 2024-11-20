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

#ifdef DFINDER_SAVE_DEVICE_LIST
#include "nstackx_device_remote.h"
#include <securec.h>
#include <stdatomic.h>
#include "nstackx_device.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_error.h"
#include "nstackx_dfinder_hidump.h"
#include "nstackx_list.h"
#include "nstackx_timer.h"
#include "nstackx_util.h"
#include "nstackx_statistics.h"
#ifdef ONE_RECORD_OF_DEVICE_FROM_ONE_LOCAL_NIF
#define RX_IFACE_REMOTE_NODE_COUNT 1
#else
#define RX_IFACE_REMOTE_NODE_COUNT 4
#endif

#define TAG "REMOTEDEVICE"
#define REPORT_INTERVAL 1000 /* 1 SECOND */
struct RxIface_;
struct RemoteDevice_;
typedef struct RemoteNode_ {
    List node;
    List orderedNode;
    DeviceInfo deviceInfo;
    struct in_addr remoteIp;
    struct RxIface_ *rxIface;
    UpdateState updateState;
    struct timespec updateTs;
} RemoteNode;

typedef struct RxIface_ {
    List node;
    NSTACKX_InterfaceInfo localIfInfo;
    List remoteNodeList;
    uint32_t remoteNodeCnt;
    struct RemoteDevice_ *device;
    struct timespec updateTime;
} RxIface;

typedef struct RemoteDevice_ {
    List node;
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    List rxIfaceList;
} RemoteDevice;

static List *g_remoteDeviceList;
static List *g_remoteDeviceListBackup;
static List *g_remoteDeviceOrderedList;
static uint32_t g_remoteNodeCount;
static atomic_uint_fast32_t g_agingTime;
static struct timespec g_lastReportedTime;
int32_t RemoteDeviceListInit(void)
{
    g_remoteDeviceList = (List *)malloc(sizeof(List));
    if (g_remoteDeviceList == NULL) {
        DFINDER_LOGE(TAG, "malloc remote device list failed");
        goto FAIL;
    }
    g_remoteDeviceListBackup = (List *)malloc(sizeof(List));
    if (g_remoteDeviceListBackup == NULL) {
        DFINDER_LOGE(TAG, "malloc remote device backup list failed");
        goto FAIL;
    }
    g_remoteDeviceOrderedList = (List *)malloc(sizeof(List));
    if (g_remoteDeviceOrderedList == NULL) {
        DFINDER_LOGE(TAG, "malloc remote device ordered list failed");
        goto FAIL;
    }
    ListInitHead(g_remoteDeviceList);
    ListInitHead(g_remoteDeviceListBackup);
    ListInitHead(g_remoteDeviceOrderedList);
    g_remoteNodeCount = 0;
    return NSTACKX_EOK;

FAIL:
    free(g_remoteDeviceList);
    g_remoteDeviceList = NULL;

    free(g_remoteDeviceListBackup);
    g_remoteDeviceListBackup = NULL;

    return NSTACKX_EFAILED;
}

static void DestroyRemoteNode(RxIface *rxIface, RemoteNode *node)
{
    ListRemoveNode(&node->node);
    ListRemoveNode(&node->orderedNode);
    if (g_remoteNodeCount > 0) {
        g_remoteNodeCount--;
    }
    if (rxIface->remoteNodeCnt > 0) {
        rxIface->remoteNodeCnt--;
    }
    free(node);
    DFINDER_LOGD(TAG, "iface %s remove a node, node count: %u, total node count: %u",
        rxIface->localIfInfo.networkName, rxIface->remoteNodeCnt, g_remoteNodeCount);
}

void DestroyRxIface(RxIface *rxIface)
{
    List *pos = NULL;
    List *tmp = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &rxIface->remoteNodeList) {
        DestroyRemoteNode(rxIface, (RemoteNode *)pos);
    }
    ListRemoveNode(&rxIface->node);
    free(rxIface);
}

void DestroyRemoteDevice(RemoteDevice *device)
{
    List *pos = NULL;
    List *tmp = NULL;
    RxIface *rxIface = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &device->rxIfaceList) {
        rxIface = (RxIface *)pos;
        DestroyRxIface(rxIface);
    }
    ListRemoveNode(&device->node);
    free(device);
}

static void DestroyRemoteNodeAndDevice(RxIface *rxIface, RemoteNode *node)
{
    DestroyRemoteNode(rxIface, node);
    if (rxIface->remoteNodeCnt == 0) {
        DestroyRemoteDevice(rxIface->device);
    }
}

static void ClearRemoteDeviceList(List *list)
{
    if (list == NULL) {
        return;
    }
    List *pos = NULL;
    List *tmp = NULL;
    RemoteDevice *device = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, list) {
        device = (RemoteDevice *)pos;
        DestroyRemoteDevice(device);
    }
}

void RemoteDeviceListDeinit(void)
{
    ClearRemoteDeviceList(g_remoteDeviceList);
    free(g_remoteDeviceList);
    g_remoteDeviceList = NULL;
    ClearRemoteDeviceList(g_remoteDeviceListBackup);
    free(g_remoteDeviceListBackup);
    g_remoteDeviceListBackup = NULL;
    free(g_remoteDeviceOrderedList);
    g_remoteDeviceOrderedList = NULL;
    g_remoteNodeCount = 0;
}

void ClearRemoteDeviceListBackup(void)
{
    ClearRemoteDeviceList(g_remoteDeviceListBackup);
}

void BackupRemoteDeviceList(void)
{
    ClearRemoteDeviceList(g_remoteDeviceListBackup);
    List *tmp = g_remoteDeviceListBackup;
    g_remoteDeviceListBackup = g_remoteDeviceList;
    g_remoteDeviceList = tmp;
    g_remoteNodeCount = 0;
}

static RemoteDevice *FindRemoteDevice(List *list, const char *deviceId)
{
    List *pos = NULL;
    RemoteDevice *device = NULL;
    LIST_FOR_EACH(pos, list) {
        device = (RemoteDevice *)pos;
        if (strcmp(device->deviceId, deviceId) == 0) {
            return device;
        }
    }
    return NULL;
}

static RxIface *FindRxIface(const RemoteDevice* device, const NSTACKX_InterfaceInfo *interfaceInfo)
{
    List *pos = NULL;
    RxIface *rxIface = NULL;
    LIST_FOR_EACH(pos, &device->rxIfaceList) {
        rxIface = (RxIface *)pos;
        if ((strcmp(interfaceInfo->networkIpAddr, rxIface->localIfInfo.networkIpAddr) == 0) &&
            (strcmp(interfaceInfo->networkName, rxIface->localIfInfo.networkName) == 0)) {
            return rxIface;
        }
    }
    return NULL;
}

static RemoteNode *FindRemoteNodeByRemoteIp(const RxIface* rxIface, const struct in_addr *remoteIp)
{
    List *pos = NULL;
    RemoteNode *remoteNode = NULL;
    LIST_FOR_EACH(pos, &rxIface->remoteNodeList) {
        remoteNode = (RemoteNode *)pos;
        if (remoteNode->remoteIp.s_addr == remoteIp->s_addr) {
            return remoteNode;
        }
    }
    return NULL;
}

static RemoteDevice *CreateRemoteDevice(const char *deviceId)
{
    RemoteDevice *device = (RemoteDevice *)calloc(1, sizeof(RemoteDevice));
    if (device == NULL) {
        DFINDER_LOGE(TAG, "malloc RemoteDevice failed");
        return NULL;
    }
    if (strcpy_s(device->deviceId, sizeof(device->deviceId), deviceId) != EOK) {
        DFINDER_LOGE(TAG, "strcpy Remote device deviceId failed");
        free(device);
        return NULL;
    }
    ListInitHead(&(device->rxIfaceList));
    return device;
}

static RxIface *CreateRxIface(RemoteDevice *device, const NSTACKX_InterfaceInfo *interfaceInfo)
{
    RxIface *rxIface = (RxIface *)calloc(1, sizeof(RxIface));
    if (rxIface == NULL) {
        DFINDER_LOGE(TAG, "malloc RxIface failed");
        return NULL;
    }
    (void)memcpy_s(&rxIface->localIfInfo, sizeof(NSTACKX_InterfaceInfo), interfaceInfo,
        sizeof(NSTACKX_InterfaceInfo));
    rxIface->device = device;
    ListInitHead(&(rxIface->remoteNodeList));
    return rxIface;
}

static uint32_t CheckAndUpdateBusinessAll(BusinessDataAll *curInfo, const BusinessDataAll *newInfo, int8_t *updated)
{
    if (newInfo->isBroadcast == NSTACKX_TRUE) {
        if (strcmp(curInfo->businessDataBroadcast, newInfo->businessDataBroadcast) != 0) {
            if (strcpy_s(curInfo->businessDataBroadcast, NSTACKX_MAX_BUSINESS_DATA_LEN,
                newInfo->businessDataBroadcast) != EOK) {
                return NSTACKX_EFAILED;
            }
            *updated = NSTACKX_TRUE;
        }
    } else {
        if (strcmp(curInfo->businessDataUnicast, newInfo->businessDataUnicast) != 0) {
            if (strcpy_s(curInfo->businessDataUnicast, NSTACKX_MAX_BUSINESS_DATA_LEN,
                newInfo->businessDataUnicast) != EOK) {
                return NSTACKX_EFAILED;
            }
            *updated = NSTACKX_TRUE;
        }
    }
    curInfo->isBroadcast = newInfo->isBroadcast;
    return NSTACKX_EOK;
}

static RemoteNode *CreateRemoteNode(RxIface *rxIface, const struct in_addr *remoteIp, const DeviceInfo *deviceInfo)
{
    RemoteNode *remoteNode = (RemoteNode *)calloc(1, sizeof(RemoteNode));
    if (remoteNode == NULL) {
        DFINDER_LOGE(TAG, "malloc RemoteNode failed");
        return NULL;
    }

    remoteNode->rxIface = rxIface;
    remoteNode->remoteIp = *remoteIp;
    remoteNode->updateState = DFINDER_UPDATE_STATE_NULL;
    (void)memcpy_s(&remoteNode->deviceInfo, sizeof(DeviceInfo), deviceInfo, sizeof(DeviceInfo));

    if (strcpy_s(remoteNode->deviceInfo.networkName, NSTACKX_MAX_INTERFACE_NAME_LEN,
        rxIface->localIfInfo.networkName) != EOK) {
        DFINDER_LOGE(TAG, "copy local report nif name failed");
        free(remoteNode);
        return NULL;
    }
    remoteNode->deviceInfo.update = NSTACKX_TRUE;
    return remoteNode;
}

static int32_t UpdateDeviceInfoBusinessData(DeviceInfo *curInfo, const DeviceInfo *newInfo, int8_t *updated)
{
    return CheckAndUpdateBusinessAll(&curInfo->businessData, &newInfo->businessData, updated);
}

static int32_t UpdateCapabilityBitmap(DeviceInfo *curInfo, const DeviceInfo *newInfo,
    int8_t *updated)
{
    /* judge capabilityBitmap is or not different with new deviceInfo */
    if ((curInfo->capabilityBitmapNum != newInfo->capabilityBitmapNum) ||
        (newInfo->capabilityBitmapNum &&
        memcmp(curInfo->capabilityBitmap, newInfo->capabilityBitmap,
               newInfo->capabilityBitmapNum * sizeof(uint32_t)))) {
        *updated = NSTACKX_TRUE;
    }

    curInfo->capabilityBitmapNum = newInfo->capabilityBitmapNum;

    (void)memset_s(curInfo->capabilityBitmap, sizeof(curInfo->capabilityBitmap), 0,
        sizeof(curInfo->capabilityBitmap));
    if (newInfo->capabilityBitmapNum) {
        if (memcpy_s(curInfo->capabilityBitmap, sizeof(curInfo->capabilityBitmap),
            newInfo->capabilityBitmap, newInfo->capabilityBitmapNum * sizeof(uint32_t)) != EOK) {
            DFINDER_LOGE(TAG, "UpdateCapabilityBitmap, capabilityBitmap copy error");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

static int32_t UpdateDeviceInfoInner(DeviceInfo *curInfo, const DeviceInfo *newInfo, int8_t *updated)
{
    if (curInfo->deviceType != newInfo->deviceType) {
        DFINDER_LOGE(TAG, "deviceType is different");
        return NSTACKX_EFAILED;
    }

    if (strcmp(curInfo->deviceName, newInfo->deviceName) != 0) {
        if (strcpy_s(curInfo->deviceName, sizeof(curInfo->deviceName), newInfo->deviceName) != EOK) {
            DFINDER_LOGE(TAG, "deviceName copy error");
            return NSTACKX_EFAILED;
        }
        *updated = NSTACKX_TRUE;
    }

    if (UpdateCapabilityBitmap(curInfo, newInfo, updated) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "UpdateCapabilityBitmap fails");
        return NSTACKX_EFAILED;
    }

    if (curInfo->mode != newInfo->mode) {
        curInfo->mode = newInfo->mode;
        *updated = NSTACKX_TRUE;
    }

    if (curInfo->businessType != newInfo->businessType) {
        curInfo->businessType = newInfo->businessType;
        *updated = NSTACKX_TRUE;
    }
    return NSTACKX_EOK;
}

static int32_t UpdateDeviceInfo(DeviceInfo *curInfo, const RxIface *rxIface, const DeviceInfo *newInfo,
    int8_t *updatedPtr)
{
    int8_t updated = NSTACKX_FALSE;
    if (UpdateDeviceInfoInner(curInfo, newInfo, &updated) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "UpdateDeviceInfoInner error");
        return NSTACKX_EFAILED;
    }

    if (strcmp(curInfo->deviceHash, newInfo->deviceHash) != 0) {
        if (strcpy_s(curInfo->deviceHash, sizeof(curInfo->deviceHash), newInfo->deviceHash) != EOK) {
            DFINDER_LOGE(TAG, "deviceHash copy error");
            return NSTACKX_EFAILED;
        }
        updated = NSTACKX_TRUE;
    }

    if (strcmp(curInfo->serviceData, newInfo->serviceData) != 0) {
        if (strcpy_s(curInfo->serviceData, NSTACKX_MAX_SERVICE_DATA_LEN, newInfo->serviceData) != EOK) {
            DFINDER_LOGE(TAG, "serviceData copy error");
            return NSTACKX_EFAILED;
        }
        updated = NSTACKX_TRUE;
    }
    updated = (newInfo->seq.dealBcast) ?
        (curInfo->seq.seqBcast != newInfo->seq.seqBcast) : (curInfo->seq.seqUcast != newInfo->seq.seqUcast);
    if (newInfo->seq.dealBcast) {
        curInfo->seq.seqBcast = newInfo->seq.seqBcast;
    } else {
        curInfo->seq.seqUcast = newInfo->seq.seqUcast;
    }
#ifndef DFINDER_USE_MINI_NSTACKX
    if (strcmp(curInfo->extendServiceData, newInfo->extendServiceData) != 0) {
        if (strcpy_s(curInfo->extendServiceData, NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN,
            newInfo->extendServiceData) != EOK) {
            DFINDER_LOGE(TAG, "extendServiceData copy error");
            return NSTACKX_EFAILED;
        }
        updated = NSTACKX_TRUE;
    }
#endif

    if (UpdateDeviceInfoBusinessData(curInfo, newInfo, &updated) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "businessData copy error");
        return NSTACKX_EFAILED;
    }

    if (strcpy_s(curInfo->networkName, NSTACKX_MAX_INTERFACE_NAME_LEN,
        rxIface->localIfInfo.networkName) != EOK) {
        DFINDER_LOGE(TAG, "copy local report nif name failed");
        return NSTACKX_EFAILED;
    }
    curInfo->discoveryType = newInfo->discoveryType;
    *updatedPtr |= updated;
    return NSTACKX_EOK;
}

static void UpdatedByTimeout(RxIface *rxIface, int8_t *updated)
{
    struct timespec cur;
    ClockGetTime(CLOCK_MONOTONIC, &cur);
    uint32_t diffMs = GetTimeDiffMs(&cur, &(rxIface->updateTime));
    if (diffMs > GetNotifyTimeoutMs()) {
        *updated = NSTACKX_TRUE;
    }
    rxIface->updateTime = cur;
}

static int32_t UpdateRemoteNode(RemoteNode *remoteNode, RxIface *rxIface, const DeviceInfo *deviceInfo,
    int8_t *updated)
{
    int32_t ret = UpdateDeviceInfo(&remoteNode->deviceInfo, rxIface, deviceInfo, updated);
    if (ret == NSTACKX_EOK && (*updated == NSTACKX_FALSE)) {
        UpdatedByTimeout(rxIface, updated);
    }
    return ret;
}

#ifdef DFINDER_DISTINGUISH_ACTIVE_PASSIVE_DISCOVERY
static void UpdateRemoteNodeChangeStateActive(UpdateState *curState, int8_t *updated)
{
    switch (*curState) {
        case DFINDER_UPDATE_STATE_NULL:
            *curState = DFINDER_UPDATE_STATE_UNICAST;
            *updated = NSTACKX_TRUE;
            break;
        case DFINDER_UPDATE_STATE_BROADCAST:
            if (*updated == NSTACKX_TRUE) {
                *curState = DFINDER_UPDATE_STATE_UNICAST;
            } else {
                *curState = DFINDER_UPDATE_STATE_ALL;
                *updated = NSTACKX_TRUE;
            }
            break;
        case DFINDER_UPDATE_STATE_UNICAST:
            break;
        case DFINDER_UPDATE_STATE_ALL:
            if (*updated == NSTACKX_TRUE) {
                *curState = DFINDER_UPDATE_STATE_UNICAST;
            }
            break;
        default:
            break;
    }
}

static void UpdateRemoteNodeChangeStatePassive(UpdateState *curState, int8_t *updated)
{
    switch (*curState) {
        case DFINDER_UPDATE_STATE_NULL:
            *curState = DFINDER_UPDATE_STATE_BROADCAST;
            *updated = NSTACKX_TRUE;
            break;
        case DFINDER_UPDATE_STATE_BROADCAST:
            break;
        case DFINDER_UPDATE_STATE_UNICAST:
            if (*updated == NSTACKX_TRUE) {
                *curState = DFINDER_UPDATE_STATE_BROADCAST;
            } else {
                *curState = DFINDER_UPDATE_STATE_ALL;
                *updated = NSTACKX_TRUE;
            }
            break;
        case DFINDER_UPDATE_STATE_ALL:
            if (*updated == NSTACKX_TRUE) {
                *curState = DFINDER_UPDATE_STATE_BROADCAST;
            }
            break;
        default:
            break;
    }
}

static void CheckAndUpdateRemoteNodeChangeState(RemoteNode *remoteNode,
    const DeviceInfo *deviceInfo, int8_t *updated)
{
    UpdateState *curState = &(remoteNode->updateState);
    if (deviceInfo->discoveryType == NSTACKX_DISCOVERY_TYPE_PASSIVE) {
        UpdateRemoteNodeChangeStatePassive(curState, updated);
    } else {
        UpdateRemoteNodeChangeStateActive(curState, updated);
    }
}
#endif /* END OF DFINDER_DISTINGUISH_ACTIVE_PASSIVE_DISCOVERY */

static void DestroyOldestRemoteNode(RxIface *rxIface)
{
    DFINDER_LOGD(TAG, "rx iface %s release the oldest remote node",
        rxIface->localIfInfo.networkName);
    List *pos = NULL;
    List *tmp = NULL;
    RemoteNode *oldestNode = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &rxIface->remoteNodeList) {
        RemoteNode *tmpNode = (RemoteNode *)pos;
        if (oldestNode == NULL || GetTimeDiffMs(&tmpNode->updateTs, &oldestNode->updateTs) == 0) {
            oldestNode = tmpNode;
        }
    }

    if (oldestNode != NULL) {
        DestroyRemoteNodeAndDevice(rxIface, oldestNode);
    }
}

static void AddRemoteNodeToList(RxIface *rxIface, RemoteNode *remoteNode)
{
    ListInsertTail(&rxIface->remoteNodeList, &remoteNode->node);
    rxIface->remoteNodeCnt++;
    g_remoteNodeCount++;
    DFINDER_LOGD(TAG, "iface %s add a node, iface node count: %u, total node count: %u",
        rxIface->localIfInfo.networkName, rxIface->remoteNodeCnt, g_remoteNodeCount);
}

void SetDeviceListAgingTime(uint32_t agingTime)
{
    if (agingTime < NSTACKX_MIN_AGING_TIME || agingTime > NSTACKX_MAX_AGING_TIME) {
        DFINDER_LOGE(TAG, "illegal agingTime passed in, set agingTime default value");
        g_agingTime = NSTACKX_DEFAULT_AGING_TIME;
        return;
    }
    g_agingTime = agingTime;
    DFINDER_LOGD(TAG, "the agingTime is set to: %u seconds", g_agingTime);
}

static bool IsAllowToBeRemoved(RemoteNode *remoteNode)
{
    struct timespec now;
    ClockGetTime(CLOCK_MONOTONIC, &now);
    uint32_t diffTime = GetTimeDiffMs(&now, &remoteNode->updateTs);
    return diffTime >= g_agingTime * NSTACKX_MILLI_TICKS;
}

static __inline RemoteNode *OrderedNodeEntry(List *node)
{
    return (RemoteNode *)((char *)(node) - (uintptr_t)(&(((RemoteNode *)0)->orderedNode)));
}

static int32_t CheckAndRemoveAgingNode(void)
{
    RemoteNode *oldestNode = OrderedNodeEntry(ListGetFront(g_remoteDeviceOrderedList));
    if (!IsAllowToBeRemoved(oldestNode)) {
        DFINDER_LOGD(TAG, "remote node count %u reach the max device num, please reset the max value",
            g_remoteNodeCount);
        struct timespec now;
        ClockGetTime(CLOCK_MONOTONIC, &now);
        uint32_t measureElapse = GetTimeDiffMs(&now, &g_lastReportedTime);
        if (measureElapse > REPORT_INTERVAL) {
            NotifyDFinderMsgRecver(DFINDER_ON_TOO_MANY_DEVICE);
            g_lastReportedTime = now;
        }
        return NSTACKX_EFAILED;
    }
    RxIface *rxIface = (RxIface *)oldestNode->rxIface;
    DestroyRemoteNodeAndDevice(rxIface, oldestNode);
    return NSTACKX_EOK;
}

void RemoveOldestNodesWithCount(uint32_t diffNum)
{
    RemoteNode *oldestNode = NULL;
    RxIface *rxIface = NULL;
    for (uint32_t i = 0; i < diffNum; i++) {
        oldestNode = OrderedNodeEntry(ListGetFront(g_remoteDeviceOrderedList));
        rxIface = (RxIface *)oldestNode->rxIface;
        DestroyRemoteNodeAndDevice(rxIface, oldestNode);
    }
}

uint32_t GetRemoteNodeCount(void)
{
    return g_remoteNodeCount;
}

static RemoteNode *CheckAndCreateRemoteNode(RxIface *rxIface,
    const struct in_addr *remoteIp, const DeviceInfo *deviceInfo)
{
    if (rxIface->remoteNodeCnt >= RX_IFACE_REMOTE_NODE_COUNT) {
        DestroyOldestRemoteNode(rxIface);
    }

    RemoteNode *remoteNode = CreateRemoteNode(rxIface, remoteIp, deviceInfo);
    if (remoteNode == NULL) {
        return NULL;
    }
    AddRemoteNodeToList(rxIface, remoteNode);
    ListInsertTail(g_remoteDeviceOrderedList, &remoteNode->orderedNode);

    return remoteNode;
}

static bool UpdateOldRemoteNode(void)
{
    if (g_remoteNodeCount == GetMaxDeviceNum() && CheckAndRemoveAgingNode() != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "remote node count %u reach the max device num", g_remoteNodeCount);
        IncStatistics(STATS_OVER_DEVICE_LIMIT);
        return false;
    }
    return true;
}

int32_t UpdateRemoteNodeByDeviceInfo(const char *deviceId, const NSTACKX_InterfaceInfo *interfaceInfo,
    const struct in_addr *remoteIp, const DeviceInfo *deviceInfo, int8_t *updated)
{
    if (!UpdateOldRemoteNode()) {
        return NSTACKX_EFAILED;
    }

    RemoteDevice *device = FindRemoteDevice(g_remoteDeviceList, deviceId);
    if (device == NULL) {
        device = CreateRemoteDevice(deviceId);
        if (device == NULL) {
            return NSTACKX_EFAILED;
        }
        ListInsertTail(g_remoteDeviceList, &(device->node));
    }

    RxIface *rxIface = FindRxIface(device, interfaceInfo);
    if (rxIface == NULL) {
        rxIface = CreateRxIface(device, interfaceInfo);
        if (rxIface == NULL) {
            goto FAIL_AND_FREE;
        }
        ClockGetTime(CLOCK_MONOTONIC, &(rxIface->updateTime));
        ListInsertTail(&(device->rxIfaceList), &(rxIface->node));
    }

    RemoteNode *remoteNode = FindRemoteNodeByRemoteIp(rxIface, remoteIp);
    if (remoteNode == NULL) {
        remoteNode = CheckAndCreateRemoteNode(rxIface, remoteIp, deviceInfo);
        if (remoteNode == NULL) {
            goto FAIL_AND_FREE;
        }
        ClockGetTime(CLOCK_MONOTONIC, &(rxIface->updateTime));
        *updated = NSTACKX_TRUE;
    } else {
        if (UpdateRemoteNode(remoteNode, rxIface, deviceInfo, updated) != NSTACKX_EOK) {
            return NSTACKX_EFAILED;
        }
        ListRemoveNode(&remoteNode->orderedNode);
        ListInsertTail(g_remoteDeviceOrderedList, &remoteNode->orderedNode);
    }
#ifdef DFINDER_DISTINGUISH_ACTIVE_PASSIVE_DISCOVERY
    CheckAndUpdateRemoteNodeChangeState(remoteNode, deviceInfo, updated);
#endif
    remoteNode->deviceInfo.update = *updated;
    ClockGetTime(CLOCK_MONOTONIC, &remoteNode->updateTs);
    return NSTACKX_EOK;

FAIL_AND_FREE:
    if (rxIface != NULL && ListIsEmpty(&rxIface->remoteNodeList)) {
        ListRemoveNode(&rxIface->node);
        free(rxIface);
    }

    if (ListIsEmpty(&device->rxIfaceList)) {
        ListRemoveNode(&device->node);
        free(device);
    }
    return NSTACKX_EFAILED;
}

static int32_t CopyRemoteNodeToDeviceInfo(DeviceInfo *deviceInfo, NSTACKX_DeviceInfo *deviceList,
    uint32_t *count, bool doFilter)
{
    if (doFilter && !MatchDeviceFilter(deviceInfo)) {
        DFINDER_LOGI(TAG, "Filter device");
        return NSTACKX_EOK;
    }

    if (GetIsNotifyPerDevice() == true && deviceInfo->update != NSTACKX_TRUE) {
        return NSTACKX_EOK;
    }

    if (GetNotifyDeviceInfo(&deviceList[*count], deviceInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "GetNotifyDeviceInfo failed");
        return NSTACKX_EFAILED;
    }

    deviceList[*count].update = deviceInfo->update;
    deviceInfo->update = NSTACKX_FALSE;
    ++(*count);
    return NSTACKX_EOK;
}

static int32_t CopyRemoteNodeListToDeviceInfo(List *rxIfaceList, NSTACKX_DeviceInfo *deviceList,
    uint32_t maxDeviceNum, uint32_t *deviceCountPtr, bool doFilter)
{
    List *pos = NULL;
    RemoteNode *remoteNode = NULL;
    int32_t ret;
    LIST_FOR_EACH(pos, rxIfaceList) {
        if (*deviceCountPtr >= maxDeviceNum) {
            break;
        }
        remoteNode = (RemoteNode *)pos;
        ret = CopyRemoteNodeToDeviceInfo(&(remoteNode->deviceInfo), deviceList, deviceCountPtr, doFilter);
        if (ret != NSTACKX_EOK) {
            DFINDER_LOGE(TAG, "copy remote node to deviceinfo failed");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

static int32_t CopyRxIfaceListToDeviceInfo(List *rxIfaceList, NSTACKX_DeviceInfo *deviceList,
    uint32_t maxDeviceNum, uint32_t *deviceCountPtr, bool doFilter)
{
    List *pos = NULL;
    RxIface *rxIface = NULL;
    LIST_FOR_EACH(pos, rxIfaceList) {
        rxIface = (RxIface *)pos;
        if (CopyRemoteNodeListToDeviceInfo(&rxIface->remoteNodeList, deviceList, maxDeviceNum,
            deviceCountPtr, doFilter) != NSTACKX_EOK) {
            DFINDER_LOGE(TAG, "copy remote node list to deviceinfo failed");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

static int32_t CopyRemoteDeviceListToDeviceInfo(NSTACKX_DeviceInfo *deviceList, uint32_t maxDeviceNum,
    uint32_t *deviceCountPtr, bool doFilter)
{
    List *pos = NULL;
    RemoteDevice *device = NULL;
    LIST_FOR_EACH(pos, g_remoteDeviceList) {
        device = (RemoteDevice *)pos;
        if (CopyRxIfaceListToDeviceInfo(&device->rxIfaceList, deviceList, maxDeviceNum,
            deviceCountPtr, doFilter) != NSTACKX_EOK) {
            DFINDER_LOGE(TAG, "copy rxIface list to deviceinfo failed");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

static void DestroyRxIfaceByIfnameInner(RemoteDevice *device, const char *ifName)
{
    List *pos = NULL;
    List *tmp = NULL;
    RxIface *rxIface = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &device->rxIfaceList) {
        rxIface = (RxIface *)pos;
        if (strcmp(rxIface->localIfInfo.networkName, ifName) == 0) {
            DFINDER_LOGD(TAG, "destroy rxIface: %s", ifName);
            DestroyRxIface(rxIface);
        }
    }
}

void DestroyRxIfaceByIfname(const char *ifName)
{
    if (g_remoteDeviceList == NULL) {
        return;
    }
    List *pos = NULL;
    List *tmp = NULL;
    RemoteDevice *device = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, g_remoteDeviceList) {
        device = (RemoteDevice *)pos;
        DestroyRxIfaceByIfnameInner(device, ifName);
    }
}

static RemoteNode *GetRxIfaceFirstRemoteNode(RxIface *rxIface)
{
    List *pos = NULL;
    RemoteNode *remoteNode = NULL;
    LIST_FOR_EACH(pos, &rxIface->remoteNodeList) {
        remoteNode = (RemoteNode *)pos;
        if (remoteNode->remoteIp.s_addr != 0) {
            return remoteNode;
        }
    }
    return NULL;
}

static RxIface *GetRemoteDevcieFirstRxIface(RemoteDevice *device)
{
    List *pos = NULL;
    RxIface *rxIface = NULL;
    LIST_FOR_EACH(pos, &device->rxIfaceList) {
        rxIface = (RxIface *)pos;
        if (!ListIsEmpty(&rxIface->remoteNodeList)) {
            return rxIface;
        }
    }
    return NULL;
}

const struct in_addr *GetRemoteDeviceIpInner(List *list, const char *deviceId)
{
    RemoteDevice *device = FindRemoteDevice(list, deviceId);
    if (device == NULL || ListIsEmpty(&device->rxIfaceList)) {
        return NULL;
    }

    RxIface *rxIface = GetRemoteDevcieFirstRxIface(device);
    if (rxIface == NULL) {
        return NULL;
    }

    RemoteNode *remoteNode = GetRxIfaceFirstRemoteNode(rxIface);
    if (remoteNode == NULL) {
        return NULL;
    }

    return &remoteNode->remoteIp;
}

const struct in_addr *GetRemoteDeviceIp(const char *deviceId)
{
    const struct in_addr *remoteIp;
    remoteIp = GetRemoteDeviceIpInner(g_remoteDeviceList, deviceId);
    if (remoteIp != NULL) {
        return remoteIp;
    }
    return GetRemoteDeviceIpInner(g_remoteDeviceListBackup, deviceId);
}

#ifdef NSTACKX_DFINDER_HIDUMP
static int DumpRemoteNode(const RemoteDevice *dev, char *buf, size_t len)
{
    List *pos = NULL;
    size_t index = 0;
    LIST_FOR_EACH(pos, &dev->rxIfaceList) {
        RxIface *rxIface = (RxIface *)pos;
        List *tmp = NULL;
        LIST_FOR_EACH(tmp, &rxIface->remoteNodeList) {
            RemoteNode *node = (RemoteNode *)tmp;
            int ret = DumpDeviceInfo(&node->deviceInfo, buf + index, len - index, NSTACKX_TRUE);
            if (ret < 0 || (size_t)ret > len - index) {
                DFINDER_LOGE(TAG, "dump remote node failed");
                return NSTACKX_EFAILED;
            }

            index += (size_t)ret;
        }
    }

    return index;
}

int DumpRemoteDevice(char *buf, size_t len)
{
    List *pos = NULL;
    size_t index = 0;
    LIST_FOR_EACH(pos, g_remoteDeviceList) {
        RemoteDevice *device = (RemoteDevice *)pos;
        int ret = DumpRemoteNode(device, buf + index, len - index);
        if (ret < 0 || (size_t)ret > len - index) {
            DFINDER_LOGE(TAG, "dump remote device failed");
            return NSTACKX_EFAILED;
        }

        index += (size_t)ret;
    }

    return index;
}
#endif

void GetDeviceList(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceListLen, bool doFilter)
{
    if (deviceList == NULL) {
        DFINDER_LOGE(TAG, "device list is null");
        return;
    }

    uint32_t maxDeviceNum = *deviceListLen;
    uint32_t count = 0;
    (void)CopyRemoteDeviceListToDeviceInfo(deviceList, maxDeviceNum, &count, doFilter);
    *deviceListLen = count;
}
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
