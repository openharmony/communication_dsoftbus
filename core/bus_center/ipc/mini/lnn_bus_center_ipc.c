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

#include "bus_center_manager.h"
#include "client_bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_log.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_time_sync_manager.h"
#include "softbus_error_code.h"

static int32_t OnRefreshDeviceFound(const char *pkgName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *additions);

static IServerDiscInnerCallback g_discInnerCb = {
    .OnServerDeviceFound = OnRefreshDeviceFound,
};

static int32_t OnRefreshDeviceFound(const char *pkgName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *additions)
{
    DeviceInfo newDevice;
    if (memcpy_s(&newDevice, sizeof(DeviceInfo), device, sizeof(DeviceInfo)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy new device info error");
        return SOFTBUS_MEM_ERR;
    }
    LnnRefreshDeviceOnlineStateAndDevIdInfo(pkgName, &newDevice, additions);
    LnnOnRefreshDeviceFound(&newDevice);
    return SOFTBUS_OK;
}

int32_t LnnIpcServerJoin(const char *pkgName, int32_t callingPid, void *addr, uint32_t addrTypeLen)
{
    (void)callingPid;
    (void)addrTypeLen;
    return LnnServerJoin((ConnectionAddr *)addr, pkgName);
}

int32_t LnnIpcServerLeave(const char *pkgName, int32_t callingPid, const char *networkId)
{
    (void)callingPid;
    return LnnServerLeave(networkId, pkgName);
}

int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen,
    int32_t *infoNum)
{
    (void)pkgName;
    if (infoTypeLen != sizeof(NodeBasicInfo)) {
        LNN_LOGE(LNN_EVENT, "infoTypeLen is invalid, infoTypeLen=%{public}d", infoTypeLen);
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

int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key, unsigned char *buf,
    uint32_t len)
{
    if (key == NODE_KEY_BLE_OFFLINE_CODE) {
        LNN_LOGE(LNN_EVENT, "the process has been abandoned");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)pkgName;
    return LnnGetNodeKeyInfo(networkId, key, buf, len);
}

int32_t LnnIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId,
    uint16_t dataChangeFlag)
{
    (void)pkgName;
    return LnnSetNodeDataChangeFlag(networkId, dataChangeFlag);
}

int32_t LnnIpcStartTimeSync(const char *pkgName, int32_t callingPid, const char *targetNetworkId,
    int32_t accuracy, int32_t period)
{
    return LnnStartTimeSync(pkgName, callingPid, targetNetworkId, (TimeSyncAccuracy)accuracy, (TimeSyncPeriod)period);
}

int32_t LnnIpcStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid)
{
    return LnnStopTimeSync(pkgName, targetNetworkId, callingPid);
}

int32_t LnnIpcPublishLNN(const char *pkgName, const PublishInfo *info)
{
    return LnnPublishService(pkgName, info, false);
}

int32_t LnnIpcStopPublishLNN(const char *pkgName, int32_t publishId)
{
    return LnnUnPublishService(pkgName, publishId, false);
}

int32_t LnnIpcRefreshLNN(const char *pkgName, int32_t callingPid, const SubscribeInfo *info)
{
    (void)callingPid;
    InnerCallback callback = {
        .serverCb = g_discInnerCb,
    };
    return LnnStartDiscDevice(pkgName, info, &callback, false);
}

int32_t LnnIpcStopRefreshLNN(const char *pkgName, int32_t callingPid, int32_t refreshId)
{
    (void)callingPid;
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

int32_t LnnIpcShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    return LnnShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
}

int32_t LnnIpcSyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen)
{
    (void)pkgName;
    (void)msg;
    (void)msgLen;
    LNN_LOGW(LNN_EVENT, "not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId,
    int32_t retCode)
{
    (void)addrTypeLen;
    return LnnOnJoinResult(addr, networkId, retCode);
}

int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return LnnOnLeaveResult(networkId, retCode);
}

int32_t LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen)
{
    (void)infoTypeLen;
    return LnnOnNodeOnlineStateChanged("", isOnline, info);
}

int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    (void)infoTypeLen;
    return LnnOnNodeBasicInfoChanged("", info, type);
}

int32_t LnnIpcNotifyNodeStatusChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    (void)info;
    (void)infoTypeLen;
    (void)type;
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}

int32_t LnnIpcLocalNetworkIdChanged(void)
{
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyDeviceTrustedChange(int32_t type, const char *msg, uint32_t msgLen)
{
    (void)type;
    (void)msg;
    (void)msgLen;
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyHichainProofException(
    const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode)
{
    (void)proofInfo;
    (void)proofLen;
    (void)deviceTypeId;
    (void)errCode;
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, int32_t pid, const void *info,
    uint32_t infoTypeLen, int32_t retCode)
{
    (void)pkgName;
    (void)pid;
    (void)infoTypeLen;
    return LnnOnTimeSyncResult(info, retCode);
}

void BusCenterServerDeathCallback(const char *pkgName)
{
    (void)pkgName;
}

int32_t LnnIpcSetDisplayName(const char *pkgName, const char *nameData, uint32_t len)
{
    (void)pkgName;
    (void)nameData;
    (void)len;
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}