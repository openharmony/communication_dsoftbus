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

#include "lnn_distributed_net_ledger.h"
#include "bus_center_manager.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnInitDistributedLedger(void)
{
    LNN_LOGI(LNN_INIT, "init virtual distribute ledger");
    return SOFTBUS_OK;
}

void LnnDeinitDistributedLedger(void)
{
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    (void)networkId;
    (void)key;
    (void)info;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDLNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    (void)networkId;
    (void)key;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    (void)info;
    return true;
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    (void)info;
    (void)infoNum;
    return SOFTBUS_NOT_IMPLEMENT;
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    (void)id;
    (void)type;
    return NULL;
}

int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len)
{
    (void)btMac;
    (void)buf;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetNetworkIdByUdidHash(const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len,
    bool needOnline)
{
    (void)udidHash;
    (void)udidHashLen;
    (void)buf;
    (void)len;
    (void)needOnline;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    (void)uuid;
    (void)buf;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    (void)udid;
    (void)buf;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    (void)id;
    (void)type;
    return true;
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    (void)id;
    (void)type;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnRemoveNode(const char *udid)
{
    (void)udid;
}

int32_t LnnUpdateNetworkId(const NodeInfo *newInfo)
{
    (void)newInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUpdateDistributedNodeInfo(NodeInfo *newInfo, const char *udid)
{
    (void)newInfo;
    (void)udid;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLDeviceNickNameByUdid(const char *udid, const char *name)
{
    (void)udid;
    (void)name;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLDeviceBroadcastCipherKey(const char *udid, const void *cipherKey)
{
    (void)udid;
    (void)cipherKey;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLDeviceBroadcastCipherIv(const char *udid, const void *cipherIv)
{
    (void)udid;
    (void)cipherIv;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLDeviceStateVersion(const char *udid, int32_t stateVersion)
{
    (void)udid;
    (void)stateVersion;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnSetDLDeviceInfoName(const char *udid, const char *name)
{
    (void)udid;
    (void)name;
    return false;
}

int32_t LnnSetDLUnifiedDeviceName(const char *udid, const char *name)
{
    (void)udid;
    (void)name;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetDLUnifiedDefaultDeviceName(const char *udid, const char *name)
{
    (void)udid;
    (void)name;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    (void)key;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDLAuthCapacity(const char *networkId, uint32_t *authCapacity)
{
    (void)networkId;
    (void)authCapacity;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    (void)networkId;
    (void)osType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum)
{
    (void)nodeNum;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetConnSubFeatureByUdidHashStr(const char *udidHashStr, uint64_t *connSubFeature)
{
    (void)udidHashStr;
    (void)connSubFeature;
    return SOFTBUS_NOT_IMPLEMENT;
}