/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <securec.h>

#include "lnn_net_ledger_deps_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_netLedgerDepsInterface;
NetLedgerDepsInterfaceMock::NetLedgerDepsInterfaceMock()
{
    g_netLedgerDepsInterface = reinterpret_cast<void *>(this);
}

NetLedgerDepsInterfaceMock::~NetLedgerDepsInterfaceMock()
{
    g_netLedgerDepsInterface = nullptr;
}

static NetLedgerDepsInterfaceMock *GetNetLedgerDepsInterface()
{
    return reinterpret_cast<NetLedgerDepsInterfaceMock *>(g_netLedgerDepsInterface);
}

extern "C" {
int32_t LnnInitModuleNotifyWithRetrySync(uint32_t module, ModuleInitCallBack callback, uint32_t retry,
    uint32_t delay)
{
    return GetNetLedgerDepsInterface()->LnnInitModuleNotifyWithRetrySync(module, callback, retry, delay);
}

int32_t LnnInitLocalLedger(void)
{
    return GetNetLedgerDepsInterface()->LnnInitLocalLedger();
}

int32_t LnnInitDistributedLedger(void)
{
    return GetNetLedgerDepsInterface()->LnnInitDistributedLedger();
}

int32_t LnnInitMetaNodeLedger(void)
{
    return GetNetLedgerDepsInterface()->LnnInitMetaNodeLedger();
}

int32_t LnnInitMetaNodeExtLedger(void)
{
    return GetNetLedgerDepsInterface()->LnnInitMetaNodeExtLedger();
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalNumU64Info(key, info);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalByteInfo(key, info, len);
}

int32_t LnnGetLocalBoolInfo(InfoKey key, bool *info, uint32_t len)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalBoolInfo(key, info, len);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalNumInfo(key, info);
}

bool IsSupportLpFeature(void)
{
    return GetNetLedgerDepsInterface()->IsSupportLpFeature();
}

int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info)
{
    return GetNetLedgerDepsInterface()->LnnSetLocalNum64Info(key, info);
}

int32_t LnnGetLocalDevInfo(NodeInfo *deviceInfo)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalDevInfo(deviceInfo);
}

void LnnDumpNodeInfo(const NodeInfo *deviceInfo, const char *log)
{
    return GetNetLedgerDepsInterface()->LnnDumpNodeInfo(deviceInfo, log);
}

int32_t LnnSaveLocalDeviceInfo(const NodeInfo *deviceInfo)
{
    return GetNetLedgerDepsInterface()->LnnSaveLocalDeviceInfo(deviceInfo);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetNetLedgerDepsInterface()->LnnSetLocalNumInfo(key, info);
}

int32_t LnnUpdateLocalNetworkId(const void *id)
{
    return GetNetLedgerDepsInterface()->LnnUpdateLocalNetworkId(id);
}

int32_t LnnUpdateLocalDeviceName(const DeviceBasicInfo *info)
{
    return GetNetLedgerDepsInterface()->LnnUpdateLocalDeviceName(info);
}

void LnnNotifyNetworkIdChangeEvent(const char *networkId)
{
    return GetNetLedgerDepsInterface()->LnnNotifyNetworkIdChangeEvent(networkId);
}

int32_t LnnUpdateLocalNetworkIdTime(int64_t time)
{
    return GetNetLedgerDepsInterface()->LnnUpdateLocalNetworkIdTime(time);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalNodeInfo();
}

void LnnInitDeviceInfoStatusSet(uint32_t module, InitDepsStatus status)
{
    return GetNetLedgerDepsInterface()->LnnInitDeviceInfoStatusSet(module, status);
}

void LnnInitSetDeviceInfoReady(void)
{
    return GetNetLedgerDepsInterface()->LnnInitSetDeviceInfoReady();
}

int32_t LnnLoadLocalDeviceInfo(void)
{
    return GetNetLedgerDepsInterface()->LnnLoadLocalDeviceInfo();
}

int32_t LnnRemoveStorageConfigPath(LnnFileId id)
{
    return GetNetLedgerDepsInterface()->LnnRemoveStorageConfigPath(id);
}

int32_t LnnUpdateLocalUuidAndIrk(void)
{
    return GetNetLedgerDepsInterface()->LnnUpdateLocalUuidAndIrk();
}

void LnnLoadPtkInfo(void)
{
    return GetNetLedgerDepsInterface()->LnnLoadPtkInfo();
}

int32_t LnnLoadRemoteDeviceInfo(void)
{
    return GetNetLedgerDepsInterface()->LnnLoadRemoteDeviceInfo();
}

void LoadBleBroadcastKey(void)
{
    return GetNetLedgerDepsInterface()->LoadBleBroadcastKey();
}

int32_t LnnLoadLocalBroadcastCipherKey(void)
{
    return GetNetLedgerDepsInterface()->LnnLoadLocalBroadcastCipherKey();
}

void AuthLoadDeviceKey(void)
{
    return GetNetLedgerDepsInterface()->AuthLoadDeviceKey();
}

int32_t LnnInitLocalLedgerDelay(void)
{
    return GetNetLedgerDepsInterface()->LnnInitLocalLedgerDelay();
}

int32_t LnnInitDecisionDbDelay(void)
{
    return GetNetLedgerDepsInterface()->LnnInitDecisionDbDelay();
}

int32_t LnnInitCommonEventMonitorImpl(void)
{
    return GetNetLedgerDepsInterface()->LnnInitCommonEventMonitorImpl();
}

void LnnDeinitMetaNodeLedger(void)
{
    return GetNetLedgerDepsInterface()->LnnDeinitMetaNodeLedger();
}

void LnnDeinitDistributedLedger(void)
{
    return GetNetLedgerDepsInterface()->LnnDeinitDistributedLedger();
}

void LnnDeinitLocalLedger(void)
{
    return GetNetLedgerDepsInterface()->LnnDeinitLocalLedger();
}

void LnnDeinitHuksInterface(void)
{
    return GetNetLedgerDepsInterface()->LnnDeinitHuksInterface();
}

void LnnDeinitMetaNodeExtLedger(void)
{
    return GetNetLedgerDepsInterface()->LnnDeinitMetaNodeExtLedger();
}

void LnnDeInitCloudSyncModule(void)
{
    return GetNetLedgerDepsInterface()->LnnDeInitCloudSyncModule();
}

int32_t LnnGetLocalNum16Info(InfoKey key, int16_t *info)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalNum16Info(key, info);
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return GetNetLedgerDepsInterface()->LnnGetRemoteStrInfo(networkId, key, info, len);
}

int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info)
{
    return GetNetLedgerDepsInterface()->LnnGetRemoteNumU32Info(networkId, key, info);
}

int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    return GetNetLedgerDepsInterface()->LnnGetRemoteNumInfo(networkId, key, info);
}

int32_t LnnGetRemoteNum16Info(const char *networkId, InfoKey key, int16_t *info)
{
    return GetNetLedgerDepsInterface()->LnnGetRemoteNum16Info(networkId, key, info);
}

int32_t LnnGetRemoteBoolInfo(const char *networkId, InfoKey key, bool *info)
{
    return GetNetLedgerDepsInterface()->LnnGetRemoteBoolInfo(networkId, key, info);
}

int32_t LnnSetLocalNum16Info(InfoKey key, int16_t info)
{
    return GetNetLedgerDepsInterface()->LnnSetLocalNum16Info(key, info);
}

int32_t LnnSetLocalNumU16Info(InfoKey key, uint16_t info)
{
    return GetNetLedgerDepsInterface()->LnnSetLocalNumU16Info(key, info);
}

int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info)
{
    return GetNetLedgerDepsInterface()->LnnSetLocalNumU32Info(key, info);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
    const unsigned char *inBuf, uint32_t inLen)
{
    return GetNetLedgerDepsInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalPtkByUuid(uuid, localPtk, len);
}

void LnnClearPtkList(void)
{
    return GetNetLedgerDepsInterface()->LnnClearPtkList();
}

void ClearDeviceInfo(void)
{
    return GetNetLedgerDepsInterface()->ClearDeviceInfo();
}

void AuthClearDeviceKey(void)
{
    return GetNetLedgerDepsInterface()->AuthClearDeviceKey();
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    return GetNetLedgerDepsInterface()->LnnGenLocalNetworkId(networkId, len);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetNetLedgerDepsInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t GenerateNewLocalCipherKey(void)
{
    return GetNetLedgerDepsInterface()->GenerateNewLocalCipherKey();
}

void LnnRemoveDb(void)
{
    return GetNetLedgerDepsInterface()->LnnRemoveDb();
}

int32_t InitTrustedDevInfoTable(void)
{
    return GetNetLedgerDepsInterface()->InitTrustedDevInfoTable();
}

int32_t LnnGenBroadcastCipherInfo(void)
{
    return GetNetLedgerDepsInterface()->LnnGenBroadcastCipherInfo();
}

int32_t HandleDeviceInfoIfUdidChanged(void)
{
    return GetNetLedgerDepsInterface()->HandleDeviceInfoIfUdidChanged();
}

int32_t LnnInitHuksInterface(void)
{
    return GetNetLedgerDepsInterface()->LnnInitHuksInterface();
}

int32_t LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len)
{
    return GetNetLedgerDepsInterface()->LnnGetRemoteByteInfo(networkId, key, info, len);
}

int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalStrInfoByIfnameIdx(key, info, len, ifIdx);
}

int32_t LnnGetRemoteStrInfoByIfnameIdx(const char *networkId, InfoKey key,
    char *info, uint32_t len, int32_t ifIdx)
{
    return GetNetLedgerDepsInterface()->LnnGetRemoteStrInfoByIfnameIdx(networkId, key, info, len, ifIdx);
}

void LnnAnonymizeDeviceStr(const char *deviceStr, uint32_t strLen, uint32_t defaultLen, char **anonymizedStr)
{
    return GetNetLedgerDepsInterface()->LnnAnonymizeDeviceStr(deviceStr, strLen, defaultLen, anonymizedStr);
}

int32_t LnnUpdateLocalHuksKeyTime(uint64_t huksKeyTime)
{
    return GetNetLedgerDepsInterface()->LnnUpdateLocalHuksKeyTime(huksKeyTime);
}

int32_t LnnGetLocalDevInfoPacked(NodeInfo *deviceInfo)
{
    return GetNetLedgerDepsInterface()->LnnGetLocalDevInfoPacked(deviceInfo);
}

bool IsSupportLpFeaturePacked(void)
{
    return GetNetLedgerDepsInterface()->IsSupportLpFeaturePacked();
}

bool LnnIsSupportLpSparkFeaturePacked(void)
{
    return GetNetLedgerDepsInterface()->LnnIsSupportLpSparkFeaturePacked();
}

int32_t LnnClearFeatureCapability(uint64_t *feature, FeatureCapability capaBit)
{
    return GetNetLedgerDepsInterface()->LnnClearFeatureCapability(feature, capaBit);
}
} // extern "C"
} // namespace OHOS