/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0g_ledger_Interface
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ledger_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_ledgerInterface;
LedgerInterfaceMock::LedgerInterfaceMock()
{
    g_ledgerInterface = reinterpret_cast<void *>(this);
}

LedgerInterfaceMock::~LedgerInterfaceMock()
{
    g_ledgerInterface = nullptr;
}

static LedgerInterface *GetLedgerInterface()
{
    return reinterpret_cast<LedgerInterfaceMock *>(g_ledgerInterface);
}

extern "C" {
int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info)
{
    return GetLedgerInterface()->LnnGetLocalDeviceInfo(info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetLedgerInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetLedgerInterface()->LnnGetLocalByteInfo(key, info, len);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetLedgerInterface()->LnnGetLocalNumInfo(key, info);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetLedgerInterface()->LnnGetNodeInfoById(id, type);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLedgerInterface()->LnnHasDiscoveryType(info, type);
}

int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp)
{
    return GetLedgerInterface()->LnnGetDLHeartbeatTimestamp(networkId, timestamp);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetLedgerInterface()->LnnGetOnlineStateById(id, type);
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    return GetLedgerInterface()->LnnGetRemoteStrInfo(netWorkId, key, info, len);
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType, DeviceLeaveReason leaveReason)
{
    return GetLedgerInterface()->LnnRequestLeaveSpecific(networkId, addrType, leaveReason);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetLedgerInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num)
{
    return GetLedgerInterface()->LnnGetTrustedDevInfoFromDb(udidArray, num);
}

const char *LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    return GetLedgerInterface()->LnnConvertDLidToUdid(id, type);
}

int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, const uint64_t timestamp)
{
    return GetLedgerInterface()->LnnSetDLHeartbeatTimestamp(networkId, timestamp);
}

int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight)
{
    return GetLedgerInterface()->LnnNotifyMasterElect(networkId, masterUdid, masterWeight);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int *target)
{
    return GetLedgerInterface()->GetJsonObjectNumberItem(json, string, target);
}

bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target)
{
    return GetLedgerInterface()->GetJsonObjectNumber64Item(json, string, target);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int num)
{
    return GetLedgerInterface()->AddNumberToJsonObject(json, string, num);
}

bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num)
{
    return GetLedgerInterface()->AddNumber64ToJsonObject(json, string, num);
}

int32_t UpdateRecoveryDeviceInfoFromDb(void)
{
    return GetLedgerInterface()->UpdateRecoveryDeviceInfoFromDb();
}

int32_t LnnGetRemoteStrInfoByIfnameIdx(const char *netWorkId, InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    return GetLedgerInterface()->LnnGetRemoteStrInfoByIfnameIdx(netWorkId, key, info, len, ifIdx);
}

int32_t LnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx)
{
    return GetLedgerInterface()->LnnGetLocalNumInfoByIfnameIdx(key, info, ifIdx);
}

void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage)
{
    return GetLedgerInterface()->DfxRecordTriggerTime(reason, stage);
}
}
int32_t LedgerInterfaceMock::ActionOfGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num)
{
    if (udidArray == nullptr || num == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    *num = 1;
    *udidArray = reinterpret_cast<char *>(SoftBusCalloc(*num * UDID_BUF_LEN));
    if (*udidArray == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    (void)strcpy_s(*udidArray, UDID_BUF_LEN, "06D1D93A2AED76215FC5EF7D8FCC551045A9DC35F0878A1E2DBA7D2D4FC9B5DA");
    return SOFTBUS_OK;
}

int32_t LedgerInterfaceMock::ActionOfLnnGetLocalStrInfo(InfoKey key, char *out, uint32_t outSize)
{
    if (key == STRING_KEY_DEV_NAME) {
        if (strcpy_s(out, outSize, deviceName.c_str()) != EOK) {
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (key == STRING_KEY_DEV_TYPE) {
        if (strcpy_s(out, outSize, TYPE_PHONE) != EOK) {
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (key == STRING_KEY_DEV_UDID) {
        if (strcpy_s(out, outSize, deviceUDID.c_str()) != EOK) {
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (key == STRING_KEY_IP) {
        if (strcpy_s(out, outSize, localIp.c_str()) != EOK) {
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int32_t LedgerInterfaceMock::ActofNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    *infoNum = 1;
    *info = reinterpret_cast<NodeBasicInfo *>(SoftBusCalloc(*infoNum * sizeof(NodeBasicInfo)));
    if (*info == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    strcpy_s((*info)->networkId, NETWORK_ID_BUF_LEN, "111222");
    strcpy_s((*info)->deviceName, DEVICE_NAME_BUF_LEN, "Device ***");
    return SOFTBUS_OK;
}
} // namespace OHOS