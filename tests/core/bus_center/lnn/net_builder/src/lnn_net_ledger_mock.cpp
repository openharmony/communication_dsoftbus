/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_net_ledger_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

using namespace testing;
using namespace testing::ext;

#define LNN_RELATION_JOIN_THREAD 1

namespace OHOS {
    
void *g_netLedgerinterface;
LnnNetLedgertInterfaceMock::LnnNetLedgertInterfaceMock()
{
    g_netLedgerinterface = reinterpret_cast<void *>(this);
}

LnnNetLedgertInterfaceMock::~LnnNetLedgertInterfaceMock()
{
    g_netLedgerinterface = nullptr;
}

static LnnNetLedgerInterface *GetNetLedgerInterface()
{
    return reinterpret_cast<LnnNetLedgerInterface *>(g_netLedgerinterface);
}

extern "C" {
int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetNetLedgerInterface()->LnnGetLocalStrInfo(key, info, len);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetNetLedgerInterface()->LnnGetLocalNodeInfo();
}

int32_t LnnGetAuthPort(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetAuthPort(info);
}

int32_t LnnGetSessionPort(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetSessionPort(info);
}

int32_t LnnGetProxyPort(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetProxyPort(info);
}

const char *LnnGetBtMac(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetBtMac(info);
}

const char *LnnGetDeviceName(const DeviceBasicInfo *info)
{
    return GetNetLedgerInterface()->LnnGetDeviceName(info);
}

char *LnnConvertIdToDeviceType(uint16_t typeId)
{
    return GetNetLedgerInterface()->LnnConvertIdToDeviceType(typeId);
}

int32_t LnnGetP2pRole(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetP2pRole(info);
}

const char *LnnGetP2pMac(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetP2pMac(info);
}

uint64_t LnnGetSupportedProtocols(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetSupportedProtocols(info);
}

int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId)
{
    return GetNetLedgerInterface()->LnnConvertDeviceTypeToId(deviceType, typeId);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetNetLedgerInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
    char *dstIdBuf, uint32_t dstIdBufLen)
{
    return GetNetLedgerInterface()->LnnConvertDlId(srcId, srcIdType,
        dstIdType, dstIdBuf, dstIdBufLen);
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetNetLedgerInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    return GetNetLedgerInterface()->LnnClearNetCapability(capability, type);
}

int32_t LnnSetP2pRole(NodeInfo *info, int32_t role)
{
    return GetNetLedgerInterface()->LnnSetP2pRole(info, role);
}

int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac)
{
    return GetNetLedgerInterface()->LnnSetP2pMac(info, p2pMac);
}

int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac)
{
    return GetNetLedgerInterface()->LnnSetP2pGoMac(info, goMac);
}

int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetNetLedgerInterface()->LnnGetAllOnlineAndMetaNodeInfo(info, infoNum);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetNetLedgerInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetNetLedgerInterface()->LnnGetNodeInfoById(id, type);
}

int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    return GetNetLedgerInterface()->LnnGetLnnRelation(id, type, relation, len);
}

int32_t LnnSetDLConnCapability(const char *networkId, uint64_t connCapability)
{
    return GetNetLedgerInterface()->LnnSetDLConnCapability(networkId, connCapability);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetNetLedgerInterface()->LnnHasDiscoveryType(info, type);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetNetLedgerInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetNetLedgerInterface()->LnnSetLocalNumInfo(key, info);
}

bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info)
{
    return GetNetLedgerInterface()->LnnSetDLP2pInfo(networkId, info);
}

bool LnnIsNodeOnline(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnIsNodeOnline(info);
}

short LnnGetCnnCode(const char *uuid, DiscoveryType type)
{
    return GetNetLedgerInterface()->LnnGetCnnCode(uuid, type);
}

ReportCategory LnnAddOnlineNode(NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnAddOnlineNode(info);
}

int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo)
{
    return GetNetLedgerInterface()->LnnGetBasicInfoByUdid(udid, basicInfo);
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    return GetNetLedgerInterface()->LnnInsertSpecificTrustedDevInfo(udid);
}

ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId)
{
    return GetNetLedgerInterface()->LnnSetNodeOffline(udid, type, authId);
}

void LnnRemoveNode(const char *udid)
{
    return GetNetLedgerInterface()->LnnRemoveNode(udid);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetDeviceUdid(info);
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline(NodeBasicInfo **info, int32_t *infoNum)
{
    if (info == NULL || infoNum == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_ERR;
    }
    *infoNum = 1;
    *info = (NodeBasicInfo *)SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo));
    if (*info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "malloc info fail");
        return SOFTBUS_ERR;
    }
    if (memcpy_s((*info)->networkId, sizeof((*info)->networkId), "abc", strlen("abc") + 1) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "memcpy networkId fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnConvertDlId(const char *srcId, IdCategory srcIdType,
    IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    if (srcId == NULL || dstIdBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(dstIdBuf, dstIdBufLen, "abc", strlen("abc") + 1) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "memcpy dstIdBuf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnConvertDlId1(const char *srcId, IdCategory srcIdType,
    IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    if (srcId == NULL || dstIdBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(dstIdBuf, dstIdBufLen, "abdef") != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "memcpy dstIdBuf fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    if (info == NULL || infoNum == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_ERR;
    }
    *infoNum = 1;
    *info = (NodeBasicInfo *)SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo));
    if (*info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "malloc info fail");
        return SOFTBUS_ERR;
    }
    if (memcpy_s((*info)->networkId, sizeof((*info)->networkId), "abc", strlen("abc") + 1) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy networkId fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation(const char *id, IdCategory type,
    uint8_t *relation, uint32_t len)
{
    if (CONNECTION_ADDR_BR >= len) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set relation fail");
        return SOFTBUS_ERR;
    }
    relation[CONNECTION_ADDR_BR] = LNN_RELATION_JOIN_THREAD;
    return SOFTBUS_OK;
}

int32_t LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(info, len, "abc", strlen("abc") + 1) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
}
}