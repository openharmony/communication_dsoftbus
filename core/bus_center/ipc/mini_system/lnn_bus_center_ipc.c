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

#include "lnn_bus_center_ipc.h"

#include <securec.h>
#include <string.h>

#include "bus_center_manager.h"
#include "client_bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_time_sync_manager.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static int32_t OnRefreshDeviceFound(const char *packageName, const DeviceInfo *device);

static IServerDiscInnerCallback g_discInnerCb = {
    .OnServerDeviceFound = OnRefreshDeviceFound,
};

static int32_t PublishResultTransfer(int32_t retCode)
{
    if (retCode == SOFTBUS_OK) {
        return PUBLISH_LNN_SUCCESS;
    } else if (retCode == SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM) {
        return PUBLISH_LNN_NOT_SUPPORT_MEDIUM;
    } else {
        return PUBLISH_LNN_INTERNAL;
    }
}

static int32_t DiscoveryResultTransfer(int32_t retCode)
{
    if (retCode == SOFTBUS_OK) {
        return REFRESH_LNN_SUCCESS;
    } else if (retCode == SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM) {
        return REFRESH_LNN_NOT_SUPPORT_MEDIUM;
    }
    return REFRESH_LNN_INTERNAL;
}

static int32_t OnRefreshDeviceFound(const char *pkgName, const DeviceInfo *device)
{
    if (LnnGetOnlineStateById(device->devId, CATEGORY_UDID)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "device has online, no need to notify sdk");
        return SOFTBUS_OK;
    }
    LnnOnRefreshDeviceFound(device);
    return SOFTBUS_OK;
}

int32_t LnnIpcServerJoin(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    (void)pkgName;
    (void)addrTypeLen;
    return LnnServerJoin((ConnectionAddr *)addr);
}

int32_t LnnIpcServerLeave(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    return LnnServerLeave(networkId);
}

int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    (void)pkgName;
    if (infoTypeLen != sizeof(NodeBasicInfo)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "infoTypeLen is invalid, infoTypeLen = %d", infoTypeLen);
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnGetAllOnlineNodeInfo((NodeBasicInfo **)info, infoNum);
}

int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)infoTypeLen;
    return LnnGetLocalDeviceInfo((NodeBasicInfo *)info);
}

int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf, uint32_t len)
{
    (void)pkgName;
    return LnnGetNodeKeyInfo(networkId, key, buf, len);
}

int32_t LnnIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    return LnnStartTimeSync(pkgName, targetNetworkId, (TimeSyncAccuracy)accuracy, (TimeSyncPeriod)period);
}

int32_t LnnIpcStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    return LnnStopTimeSync(pkgName, targetNetworkId);
}

int32_t LnnIpcPublishLNN(const char *pkgName, const PublishInfo *info)
{
    int32_t ret = LnnPublishService(pkgName, info, false);
    LnnOnPublishLNNResult(info->publishId, PublishResultTransfer(ret));
    return SOFTBUS_OK;
}

int32_t LnnIpcStopPublishLNN(const char *pkgName, int32_t publishId)
{
    return LnnUnPublishService(pkgName, publishId, false);
}

int32_t LnnIpcRefreshLNN(const char *pkgName, const SubscribeInfo *info)
{
    SetCallLnnStatus(false);
    InnerCallback callback = {
        .serverCb = g_discInnerCb,
    };
    int32_t ret = LnnStartDiscDevice(pkgName, info, &callback, false);
    LnnOnRefreshLNNResult(info->subscribeId, DiscoveryResultTransfer(ret));
    return SOFTBUS_OK;
}

int32_t LnnIpcStopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    return LnnStopDiscDevice(pkgName, refreshId, false);
}

int32_t LnnIpcActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    return LnnActiveMetaNode(info, metaNodeId);
}

int32_t LnnIpcDeactiveMetaNode(const char *metaNodeId)
{
    return LnnDeactiveMetaNode(metaNodeId);
}

int32_t LnnIpcGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    return LnnGetAllMetaNodeInfo(infos, infoNum);
}

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode)
{
    return LnnOnJoinResult(addr, networkId, retCode);
}

int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return LnnOnLeaveResult(networkId, retCode);
}

int32_t LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return LnnOnNodeOnlineStateChanged(isOnline, info);
}

int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return LnnOnNodeBasicInfoChanged(info, type);
}

int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    (void)pkgName;
    (void)infoTypeLen;
    return LnnOnTimeSyncResult(info, retCode);
}

void BusCenterServerDeathCallback(const char *pkgName)
{
    (void)pkgName;
}
