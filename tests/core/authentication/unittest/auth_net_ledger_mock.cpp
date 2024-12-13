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

#include "auth_net_ledger_mock.h"
#include "auth_connection.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "softbus_adapter_mem.h"
#include "string"

static const std::string CMD_TAG = "TECmd";
static const std::string CMD_GET_AUTH_INFO = "getAuthInfo";
static const std::string CMD_RET_AUTH_INFO = "retAuthInfo";
static const std::string DATA_TAG = "TEData";
static const std::string DEVICE_ID_TAG = "TEDeviceId";
static const std::string DATA_BUF_SIZE_TAG = "DataBufSize";
static const std::string SOFT_BUS_VERSION_TAG = "softbusVersion";
static const int32_t PACKET_SIZE = (64 * 1024);

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_netLedgerinterface;
AuthNetLedgertInterfaceMock::AuthNetLedgertInterfaceMock()
{
    g_netLedgerinterface = reinterpret_cast<void *>(this);
}

AuthNetLedgertInterfaceMock::~AuthNetLedgertInterfaceMock()
{
    g_netLedgerinterface = nullptr;
}

static AuthNetLedgerInterface *GetNetLedgerInterface()
{
    return reinterpret_cast<AuthNetLedgertInterfaceMock *>(g_netLedgerinterface);
}

extern "C" {
int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetNetLedgerInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId)
{
    return GetNetLedgerInterface()->LnnDeleteSpecificTrustedDevInfo(udid, localUserId);
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

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetDeviceUdid(info);
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

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetNetLedgerInterface()->LnnGetNodeInfoById(id, type);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetNetLedgerInterface()->LnnHasDiscoveryType(info, type);
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    return GetNetLedgerInterface()->LnnGetNetworkIdByUdid(udid, buf, len);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return GetNetLedgerInterface()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

int32_t LnnSetSupportDiscoveryType(char *info, const char *type)
{
    return GetNetLedgerInterface()->LnnSetSupportDiscoveryType(info, type);
}

bool LnnHasSupportDiscoveryType(const char *destType, const char *type)
{
    return GetNetLedgerInterface()->LnnHasSupportDiscoveryType(destType, type);
}

bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetNetLedgerInterface()->LnnPeerHasExchangeDiscoveryType(info, type);
}

void RouteBuildClientAuthManager(int32_t cfd)
{
    return GetNetLedgerInterface()->RouteBuildClientAuthManager(cfd);
}

void RouteClearAuthChannelId(int32_t cfd)
{
    return GetNetLedgerInterface()->RouteClearAuthChannelId(cfd);
}

bool GetJsonObjectStringItem(const cJSON *json, const char * const string, char *target, uint32_t targetLen)
{
    return GetNetLedgerInterface()->GetJsonObjectStringItem(json, string, target, targetLen);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool LnnSetDlPtk(const char *networkId, const char *remotePtk)
{
    return GetNetLedgerInterface()->LnnSetDlPtk(networkId, remotePtk);
}

void LnnDumpRemotePtk(const char *oldPtk, const char *newPtk, const char *log)
{
    return GetNetLedgerInterface()->LnnDumpRemotePtk(oldPtk, newPtk, log);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetNetLedgerInterface()->LnnGetOnlineStateById(id, type);
}

int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetLocalNodeInfoSafe(info);
}
}

char *AuthNetLedgertInterfaceMock::Pack(int64_t authSeq, const AuthSessionInfo *info, AuthDataHead &head)
{
    cJSON *obj = cJSON_CreateObject();
    if (obj == nullptr) {
        return nullptr;
    }
    char uuid[UUID_BUF_LEN] = "33654";
    char udid[UDID_BUF_LEN] = "15464";
    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI && !info->isServer) {
        if (!AddStringToJsonObject(obj, CMD_TAG.c_str(), CMD_GET_AUTH_INFO.c_str())) {
            cJSON_Delete(obj);
            return nullptr;
        }
    } else {
        if (!AddStringToJsonObject(obj, CMD_TAG.c_str(), CMD_RET_AUTH_INFO.c_str())) {
            cJSON_Delete(obj);
            return nullptr;
        }
    }
    if (!AddStringToJsonObject(obj, DATA_TAG.c_str(), uuid) ||
        !AddStringToJsonObject(obj, DEVICE_ID_TAG.c_str(), udid) ||
        !AddNumberToJsonObject(obj, DATA_BUF_SIZE_TAG.c_str(), PACKET_SIZE) ||
        !AddNumberToJsonObject(obj, SOFT_BUS_VERSION_TAG.c_str(), SOFTBUS_NEW_V1)) {
        AUTH_LOGE(AUTH_TEST, "add msg body fail.");
        cJSON_Delete(obj);
        return nullptr;
    }
    char *msg = cJSON_PrintUnformatted(obj);
    if (msg == nullptr) {
        cJSON_Delete(obj);
        return nullptr;
    }
    cJSON_Delete(obj);
    head.len = static_cast<uint32_t>(strlen(msg) + 1);
    uint32_t size = GetAuthDataSize(head.len);
    uint8_t *buf = reinterpret_cast<uint8_t *>(SoftBusMalloc(size));
    if (buf == nullptr) {
        cJSON_free(msg);
        return nullptr;
    }
    int32_t ret = PackAuthData(&head, reinterpret_cast<uint8_t *>(msg), buf, size);
    if (ret == SOFTBUS_OK) {
        cJSON_free(msg);
        AUTH_LOGI(AUTH_TEST, "PackAuthData success.");
        return reinterpret_cast<char *>(buf);
    }
    SoftBusFree(buf);
    cJSON_free(msg);
    return nullptr;
}

void AuthNetLedgertInterfaceMock::OnDeviceVerifyPass(AuthHandle authHandle, const NodeInfo *info)
{
    AUTH_LOGI(AUTH_TEST, "Device verify passed & send cond");
    (void)authHandle;
    (void)info;
    if (SoftBusMutexLock(&LnnHichainInterfaceMock::mutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_TEST, "Device verify Lock failed");
        return;
    }
    isRuned = true;
    SoftBusCondSignal(&LnnHichainInterfaceMock::cond);
    SoftBusMutexUnlock(&LnnHichainInterfaceMock::mutex);
}

void AuthNetLedgertInterfaceMock::OnDeviceNotTrusted(const char *peerUdid)
{
    AUTH_LOGI(AUTH_TEST, "Device not trusted call back & send cond");
    (void)peerUdid;
    if (SoftBusMutexLock(&LnnHichainInterfaceMock::mutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_TEST, "Device not trusted Lock failed");
        return;
    }
    isRuned = true;
    SoftBusCondSignal(&LnnHichainInterfaceMock::cond);
    SoftBusMutexUnlock(&LnnHichainInterfaceMock::mutex);
}

void AuthNetLedgertInterfaceMock::OnDeviceDisconnect(AuthHandle authHandle)
{
    AUTH_LOGI(AUTH_TEST, "Device disconnect call back & send cond");
    (void)authHandle;
    if (SoftBusMutexLock(&LnnHichainInterfaceMock::mutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_TEST, "Device disconnect Lock failed");
        return;
    }
    isRuned = true;
    SoftBusCondSignal(&LnnHichainInterfaceMock::cond);
    SoftBusMutexUnlock(&LnnHichainInterfaceMock::mutex);
}
} // namespace OHOS