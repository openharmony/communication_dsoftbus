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

#include "bus_center_server_proxy.h"

#include "securec.h"

#include "lnn_bus_center_ipc.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

int32_t BusCenterServerProxyInit(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center get server proxy ok");
    return SOFTBUS_OK;
}

void BusCenterServerProxyDeInit(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center delete server proxy ok");
}

int32_t ServerIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum)
{
    return LnnIpcGetAllOnlineNodeInfo(pkgName, info, infoTypeLen, infoNum);
}

int32_t ServerIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    return LnnIpcGetLocalDeviceInfo(pkgName, info, infoTypeLen);
}

int32_t ServerIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf, uint32_t len)
{
    return LnnIpcGetNodeKeyInfo(pkgName, networkId, key, buf, len);
}

int32_t ServerIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    return LnnIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
}

int32_t ServerIpcJoinLNN(const char *pkgName, void *addr, unsigned int addrTypeLen)
{
    return LnnIpcServerJoin(pkgName, addr, addrTypeLen);
}

int32_t ServerIpcJoinMetaNode(const char *pkgName, void *addr, CustomData *customData, unsigned int addrTypeLen)
{
    (void)pkgName;
    (void)addr;
    (void)customData;
    (void)addrTypeLen;
    return SOFTBUS_OK;
}

int32_t ServerIpcLeaveLNN(const char *pkgName, const char *networkId)
{
    return LnnIpcServerLeave(pkgName, networkId);
}

int32_t ServerIpcLeaveMetaNode(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    (void)networkId;
    return SOFTBUS_OK;
}

int32_t ServerIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    return LnnIpcStartTimeSync(pkgName, targetNetworkId, accuracy, period);
}

int32_t ServerIpcStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    return LnnIpcStopTimeSync(pkgName, targetNetworkId);
}

int32_t ServerIpcPublishLNN(const char *pkgName, const void *info, uint32_t infoLen)
{
    return LnnIpcPublishLNN(pkgName, info, infoLen);
}

int32_t ServerIpcStopPublishLNN(const char *pkgName, int32_t publishId)
{
    return LnnIpcStopPublishLNN(pkgName, publishId);
}

int32_t ServerIpcRefreshLNN(const char *pkgName, const void *info, uint32_t infoTypeLen)
{
    return LnnIpcRefreshLNN(pkgName, info, infoTypeLen);
}

int32_t ServerIpcStopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    return LnnIpcStopRefreshLNN(pkgName, refreshId);
}

int32_t ServerIpcActiveMetaNode(const char *pkgName, const MetaNodeConfigInfo *info, char *metaNodeId)
{
    (void)pkgName;
    return LnnIpcActiveMetaNode(info, metaNodeId);
}

int32_t ServerIpcDeactiveMetaNode(const char *pkgName, const char *metaNodeId)
{
    (void)pkgName;
    return LnnIpcDeactiveMetaNode(metaNodeId);
}

int32_t ServerIpcGetAllMetaNodeInfo(const char *pkgName, MetaNodeInfo *infos, int32_t *infoNum)
{
    (void)pkgName;
    return LnnIpcGetAllMetaNodeInfo(infos, infoNum);
}

int32_t ServerIpcShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    return LnnIpcShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
}