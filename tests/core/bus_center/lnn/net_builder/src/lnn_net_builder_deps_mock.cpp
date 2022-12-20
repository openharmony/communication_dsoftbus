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

#include "lnn_net_builder_deps_mock.h"

#include <gtest/gtest.h>
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_netBuilderDepsInterface;
NetBuilderDepsInterfaceMock::NetBuilderDepsInterfaceMock()
{
    g_netBuilderDepsInterface = reinterpret_cast<void *>(this);
}

NetBuilderDepsInterfaceMock::~NetBuilderDepsInterfaceMock()
{
    g_netBuilderDepsInterface = nullptr;
}

static NetBuilderDepsInterface *GetNetBuilderDepsInterface()
{
    return reinterpret_cast<NetBuilderDepsInterfaceMock *>(g_netBuilderDepsInterface);
}

int32_t NetBuilderDepsInterfaceMock::ActionOfLnnGetSettingDeviceName(char *deviceName, uint32_t len)
{
    if (deviceName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(deviceName, len, "abc", strlen("abc") + 1) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

extern "C" {
int32_t LnnGetSettingDeviceName(char *deviceName, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGetSettingDeviceName(deviceName, len);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetNetBuilderDepsInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t LnnDeleteMetaInfo(const char *udid, ConnectionAddrType type)
{
    return GetNetBuilderDepsInterface()->LnnDeleteMetaInfo(udid, type);
}

int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t* connId)
{
    return GetNetBuilderDepsInterface()->TransGetConnByChanId(channelId, channelType, connId);
}

int32_t AuthMetaStartVerify(uint32_t connectionId, const uint8_t *key, uint32_t keyLen,
    uint32_t requestId, const AuthVerifyCallback *callBack)
{
    return GetNetBuilderDepsInterface()->AuthMetaStartVerify(connectionId, key, keyLen, requestId, callBack);
}

uint32_t AuthGenRequestId(void)
{
    return GetNetBuilderDepsInterface()->AuthGenRequestId();
}

void AuthHandleLeaveLNN(int64_t authId)
{
    return GetNetBuilderDepsInterface()->AuthHandleLeaveLNN(authId);
}

int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetNetBuilderDepsInterface()->SoftbusGetConfig(type, val, len);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetNetBuilderDepsInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetNetBuilderDepsInterface()->LnnSetLocalNumInfo(key, info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetNetBuilderDepsInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGetNetworkIdByUdid(udid, buf, len);
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGetRemoteStrInfo(netWorkId, key, info, len);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return GetNetBuilderDepsInterface()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2)
{
    return GetNetBuilderDepsInterface()->LnnIsSameConnectionAddr(addr1, addr2);
}

bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option)
{
    return GetNetBuilderDepsInterface()->LnnConvertAddrToOption(addr, option);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return GetNetBuilderDepsInterface()->LnnConvAddrTypeToDiscType(type);
}

ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type)
{
    return GetNetBuilderDepsInterface()->LnnDiscTypeToConnAddrType(type);
}

bool LnnConvertAuthConnInfoToAddr(ConnectionAddr *addr, const AuthConnInfo *connInfo, ConnectionAddrType hintType)
{
    return GetNetBuilderDepsInterface()->LnnConvertAuthConnInfoToAddr(addr, connInfo, hintType);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetNetBuilderDepsInterface()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int num)
{
    return GetNetBuilderDepsInterface()->AddNumberToJsonObject(json, string, num);
}

int32_t LnnSendSyncInfoMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg,
    uint32_t len, LnnSyncInfoMsgComplete complete)
{
    return GetNetBuilderDepsInterface()->LnnSendSyncInfoMsg(type, networkId, msg, len, complete);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetNetBuilderDepsInterface()->LnnGetNodeInfoById(id, type);
}

int32_t LnnUpdateNodeInfo(NodeInfo *newInfo)
{
    return GetNetBuilderDepsInterface()->LnnUpdateNodeInfo(newInfo);
}

int32_t LnnAddMetaInfo(NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnAddMetaInfo(info);
}

int32_t LnnGetAllAuthSeq(const char *udid, int64_t *authSeq, uint32_t num)
{
    return GetNetBuilderDepsInterface()->LnnGetAllAuthSeq(udid, authSeq, num);
}

int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
    char *dstIdBuf, uint32_t dstIdBufLen)
{
    return GetNetBuilderDepsInterface()->LnnConvertDlId(srcId, srcIdType, dstIdType, dstIdBuf, dstIdBufLen);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetNetBuilderDepsInterface()->LnnGetOnlineStateById(id, type);
}

bool LnnIsNodeOnline(const NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnIsNodeOnline(info);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnGetDeviceUdid(info);
}

int32_t LnnCompareNodeWeight(int32_t weight1, const char *masterUdid1, int32_t weight2, const char *masterUdid2)
{
    return GetNetBuilderDepsInterface()->LnnCompareNodeWeight(weight1, masterUdid1, weight2, masterUdid2);
}

void LnnNotifyAllTypeOffline(ConnectionAddrType type)
{
    return GetNetBuilderDepsInterface()->LnnNotifyAllTypeOffline(type);
}

int32_t SoftBusGetTime(SoftBusSysTime *sysTime)
{
    return GetNetBuilderDepsInterface()->SoftBusGetTime(sysTime);
}

int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *connInfo)
{
    return GetNetBuilderDepsInterface()->AuthGetConnInfo(authId, connInfo);
}

void MetaNodeNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->MetaNodeNotifyJoinResult(addr, networkId, retCode);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->LnnNotifyLeaveResult(networkId, retCode);
}

int32_t MetaNodeIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->MetaNodeIpcNotifyJoinResult(addr, addrTypeLen, networkId, retCode);
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    return GetNetBuilderDepsInterface()->LnnGetAddrTypeByIfName(ifName, type);
}

int32_t LnnSendNotTrustedInfo(NotTrustedDelayInfo *info, uint32_t num)
{
    return GetNetBuilderDepsInterface()->LnnSendNotTrustedInfo(info, num);
}

int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis)
{
    return GetNetBuilderDepsInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

SoftBusLooper *GetLooper(int looper)
{
    return GetNetBuilderDepsInterface()->GetLooper(looper);
}

int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option)
{
    return GetNetBuilderDepsInterface()->ConnDisconnectDeviceAllConn(option);
}

int32_t LnnGenLocalUuid(char *uuid, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGenLocalUuid(uuid, len);
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGenLocalNetworkId(networkId, len);
}

int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr)
{
    return GetNetBuilderDepsInterface()->LnnSetDLNodeAddr(id, type, addr);
}

int32_t LnnInitP2p(void)
{
    return GetNetBuilderDepsInterface()->LnnInitP2p();
}

void LnnDeinitP2p(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitP2p();
}

int32_t LnnInitNetworkInfo(void)
{
    return GetNetBuilderDepsInterface()->LnnInitNetworkInfo();
}

int32_t LnnInitDevicename(void)
{
    return GetNetBuilderDepsInterface()->LnnInitDevicename();
}

int32_t LnnInitSyncInfoManager(void)
{
    return GetNetBuilderDepsInterface()->LnnInitSyncInfoManager();
}

void LnnDeinitSyncInfoManager(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitSyncInfoManager();
}

int32_t LnnInitTopoManager(void)
{
    return GetNetBuilderDepsInterface()->LnnInitTopoManager();
}

void LnnDeinitTopoManager(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitTopoManager();
}

int32_t RegAuthVerifyListener(const AuthVerifyListener *listener)
{
    return GetNetBuilderDepsInterface()->RegAuthVerifyListener(listener);
}

void UnregAuthVerifyListener(void)
{
    return GetNetBuilderDepsInterface()->UnregAuthVerifyListener();
}

int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetNetBuilderDepsInterface()->LnnRegSyncInfoHandler(type, handler);
}

int32_t LnnUnregSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetNetBuilderDepsInterface()->LnnUnregSyncInfoHandler(type, handler);
}

int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback)
{
    return GetNetBuilderDepsInterface()->LnnStopConnectionFsm(connFsm, callback);
}

void LnnDeinitFastOffline(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitFastOffline();
}

int32_t OnJoinMetaNode(MetaJoinRequestNode *mateJoinNode, CustomData *customData)
{
    return GetNetBuilderDepsInterface()->OnJoinMetaNode(mateJoinNode, customData);
}

int32_t LnnSendNewNetworkOnlineToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendNewNetworkOnlineToConnFsm(connFsm);
}

int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->LnnSendAuthResultMsgToConnFsm(connFsm, retCode);
}

int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendDisconnectMsgToConnFsm(connFsm);
}

int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendNotTrustedToConnFsm(connFsm);
}

int32_t LnnSendLeaveRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendLeaveRequestToConnFsm(connFsm);
}

int32_t LnnSendSyncOfflineFinishToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendSyncOfflineFinishToConnFsm(connFsm);
}

int32_t LnnGetLocalWeight(void)
{
    return GetNetBuilderDepsInterface()->LnnGetLocalWeight();
}

void AuthMetaReleaseVerify(int64_t authId)
{
    return GetNetBuilderDepsInterface()->AuthMetaReleaseVerify(authId);
}

void MetaNodeNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->MetaNodeNotifyLeaveResult(networkId, retCode);
}

int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendJoinRequestToConnFsm(connFsm);
}

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->LnnNotifyJoinResult(addr, networkId, retCode);
}

void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnDestroyConnectionFsm(connFsm);
}

LnnConnectionFsm *LnnCreateConnectionFsm(const ConnectionAddr *target)
{
    return GetNetBuilderDepsInterface()->LnnCreateConnectionFsm(target);
}

int64_t LnnUpTimeMs(void)
{
    return GetNetBuilderDepsInterface()->LnnUpTimeMs();
}

int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnStartConnectionFsm(connFsm);
}

void LnnNotifyMasterNodeChanged(bool isMaster, const char* masterNodeUdid, int32_t weight)
{
    return GetNetBuilderDepsInterface()->LnnNotifyMasterNodeChanged(isMaster, masterNodeUdid, weight);
}

int32_t LnnInitFastOffline(void)
{
    return GetNetBuilderDepsInterface()->LnnInitFastOffline();
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetNetBuilderDepsInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

void LnnNotifyNodeAddressChanged(const char* addr)
{
    return GetNetBuilderDepsInterface()->LnnNotifyNodeAddressChanged(addr);
}

int32_t LnnInitOffline(void)
{
    return GetNetBuilderDepsInterface()->LnnInitOffline();
}

void LnnDeinitOffline(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitOffline();
}

} // extern "C"
} // namespace OHOS
