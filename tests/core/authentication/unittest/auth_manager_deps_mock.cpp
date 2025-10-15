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

#include "auth_manager_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_authManagerIf;
AuthManagerInterfaceMock::AuthManagerInterfaceMock()
{
    g_authManagerIf = static_cast<void *>(this);
}

AuthManagerInterfaceMock::~AuthManagerInterfaceMock()
{
    g_authManagerIf = nullptr;
}

static AuthManagerInterface *GetAuthMangerIf()
{
    return static_cast<AuthManagerInterface *>(g_authManagerIf);
}
extern "C" {
bool CheckAuthConnInfoType(const AuthConnInfo *connInfo)
{
    return GetAuthMangerIf()->CheckAuthConnInfoType(connInfo);
}

void InitSessionKeyList(SessionKeyList *list)
{
    return GetAuthMangerIf()->InitSessionKeyList(list);
}

const char *GetAuthSideStr(bool isServer)
{
    return GetAuthMangerIf()->GetAuthSideStr(isServer);
}

uint8_t *DupMemBuffer(const uint8_t *buf, uint32_t size)
{
    return GetAuthMangerIf()->DupMemBuffer(buf, size);
}

int32_t DupSessionKeyList(const SessionKeyList *srcList, SessionKeyList *dstList)
{
    return GetAuthMangerIf()->DupSessionKeyList(srcList, dstList);
}

void DestroySessionKeyList(SessionKeyList *list)
{
    return GetAuthMangerIf()->DestroySessionKeyList(list);
}

void ClearSessionkeyByAuthLinkType(int64_t authId, SessionKeyList *list, AuthLinkType type)
{
    return GetAuthMangerIf()->ClearSessionkeyByAuthLinkType(authId, list, type);
}

void CancelUpdateSessionKey(int64_t authId)
{
    return GetAuthMangerIf()->CancelUpdateSessionKey(authId);
}

bool CompareConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash)
{
    return GetAuthMangerIf()->CompareConnInfo(info1, info2, cmpShortHash);
}

int32_t GetConnType(uint64_t connId)
{
    return GetAuthMangerIf()->GetConnType(connId);
}

void RemoveSessionkeyByIndex(SessionKeyList *list, int32_t index, AuthLinkType type)
{
    return GetAuthMangerIf()->RemoveSessionkeyByIndex(list, index, type);
}

bool CheckSessionKeyListExistType(const SessionKeyList *list, AuthLinkType type)
{
    return GetAuthMangerIf()->CheckSessionKeyListExistType(list, type);
}

void AuthRemoveDeviceKeyByUdid(const char *udidOrHash)
{
    return GetAuthMangerIf()->AuthRemoveDeviceKeyByUdid(udidOrHash);
}

int32_t LnnNotifyEmptySessionKey(int64_t authId)
{
    return GetAuthMangerIf()->LnnNotifyEmptySessionKey(authId);
}

int32_t LnnNotifyLeaveLnnByAuthHandle(AuthHandle *authHandle)
{
    return GetAuthMangerIf()->LnnNotifyLeaveLnnByAuthHandle(authHandle);
}

void PrintAuthConnInfo(const AuthConnInfo *connInfo)
{
    return GetAuthMangerIf()->PrintAuthConnInfo(connInfo);
}

uint64_t GetLatestAvailableSessionKeyTime(const SessionKeyList *list, AuthLinkType type)
{
    return GetAuthMangerIf()->GetLatestAvailableSessionKeyTime(list, type);
}

uint64_t GetCurrentTimeMs(void)
{
    return GetAuthMangerIf()->GetCurrentTimeMs();
}

int32_t SetSessionKeyAuthLinkType(const SessionKeyList *list, int32_t index, AuthLinkType type)
{
    return GetAuthMangerIf()->SetSessionKeyAuthLinkType(list, index, type);
}

int32_t AddSessionKey(SessionKeyList *list, int32_t index, const SessionKey *key,
    AuthLinkType type, bool isOldKey)
{
    return GetAuthMangerIf()->AddSessionKey(list, index, key, type, isOldKey);
}

AuthFsm *GetAuthFsmByConnId(uint64_t connId, bool isServer, bool isConnectSide)
{
    return GetAuthMangerIf()->GetAuthFsmByConnId(connId, isServer, isConnectSide);
}

void DisconnectAuthDevice(uint64_t *connId)
{
    return GetAuthMangerIf()->DisconnectAuthDevice(connId);
}

int32_t ClearOldKey(const SessionKeyList *list, AuthLinkType type)
{
    return GetAuthMangerIf()->ClearOldKey(list, type);
}

int32_t SetSessionKeyAvailable(SessionKeyList *list, int32_t index)
{
    return GetAuthMangerIf()->SetSessionKeyAvailable(list, index);
}

int32_t GetSessionKeyByIndex(const SessionKeyList *list, int32_t index, AuthLinkType type, SessionKey *key)
{
    return GetAuthMangerIf()->GetSessionKeyByIndex(list, index, type, key);
}

void ScheduleUpdateSessionKey(AuthHandle authHandle, uint64_t delatMs)
{
    return GetAuthMangerIf()->ScheduleUpdateSessionKey(authHandle, delatMs);
}

int64_t GenSeq(bool isServer)
{
    return GetAuthMangerIf()->GenSeq(isServer);
}

int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request)
{
    return GetAuthMangerIf()->GetAuthRequest(requestId, request);
}

void AuthNotifyDeviceVerifyPassed(AuthHandle authHandle, const NodeInfo *nodeInfo)
{
    return GetAuthMangerIf()->AuthNotifyDeviceVerifyPassed(authHandle, nodeInfo);
}

bool CheckAuthConnCallback(const AuthConnCallback *connCb)
{
    return GetAuthMangerIf()->CheckAuthConnCallback(connCb);
}

void PerformAuthConnCallback(uint32_t requestId, int32_t result, int64_t authId)
{
    return GetAuthMangerIf()->PerformAuthConnCallback(requestId, result, authId);
}

void DelAuthRequest(uint32_t requestId)
{
    return GetAuthMangerIf()->DelAuthRequest(requestId);
}

int32_t AuthStartReconnectDevice(AuthHandle authHandle, const AuthConnInfo *connInfo,
    uint32_t requestId, const AuthConnCallback *connCb)
{
    return GetAuthMangerIf()->AuthStartReconnectDevice(authHandle, connInfo, requestId, connCb);
}

void PerformVerifyCallback(uint32_t requestId, int32_t result, AuthHandle authHandle, const NodeInfo *info)
{
    return GetAuthMangerIf()->PerformVerifyCallback(requestId, result, authHandle, info);
}

int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data)
{
    return GetAuthMangerIf()->PostAuthData(connId, toServer, head, data);
}

void DelAuthNormalizeRequest(int64_t authSeq)
{
    return GetAuthMangerIf()->DelAuthNormalizeRequest(authSeq);
}

void UpdateAuthDevicePriority(uint64_t connId)
{
    return GetAuthMangerIf()->UpdateAuthDevicePriority(connId);
}

bool LnnSetDlPtk(const char *networkId, const char *remotePtk)
{
    return GetAuthMangerIf()->LnnSetDlPtk(networkId, remotePtk);
}

int32_t GetIsExchangeUdidByNetworkId(const char *networkId, bool *isExchangeUdid)
{
    return GetAuthMangerIf()->GetIsExchangeUdidByNetworkId(networkId, isExchangeUdid);
}

void LnnClearAuthExchangeUdid(const char *networkId)
{
    return GetAuthMangerIf()->LnnClearAuthExchangeUdid(networkId);
}

void AuthNotifyDeviceDisconnect(AuthHandle authHandle)
{
    return GetAuthMangerIf()->AuthNotifyDeviceDisconnect(authHandle);
}

void AuthAddNodeToLimitMap(const char *udid, int32_t reason)
{
    return GetAuthMangerIf()->AuthAddNodeToLimitMap(udid, reason);
}

int32_t PostAuthEvent(EventType event, EventHandler handler,
    const void *obj, uint32_t size, uint64_t delayMs)
{
    return GetAuthMangerIf()->PostAuthEvent(event, handler, obj, size, delayMs);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetAuthMangerIf()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetAuthMangerIf()->LnnGetLocalNumU64Info(key, info);
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return GetAuthMangerIf()->IsFeatureSupport(feature, capaBit);
}

void AuthDeleteLimitMap(const char *udidHash)
{
    return GetAuthMangerIf()->AuthDeleteLimitMap(udidHash);
}

int32_t AuthSessionStartAuth(const AuthParam *authParam, const AuthConnInfo *connInfo,
    const DeviceKeyId *deviceKeyId)
{
    return GetAuthMangerIf()->AuthSessionStartAuth(authParam, connInfo, deviceKeyId);
}

void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo)
{
    return GetAuthMangerIf()->GetLnnTriggerInfo(triggerInfo);
}

int32_t AuthSessionProcessDevIdData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    return GetAuthMangerIf()->AuthSessionProcessDevIdData(authSeq, data, len);
}

bool GetConfigSupportAsServer(void)
{
    return GetAuthMangerIf()->GetConfigSupportAsServer();
}

void HandleRepeatDeviceIdDataDelay(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data)
{
    return GetAuthMangerIf()->HandleRepeatDeviceIdDataDelay(connId, connInfo, fromServer, head, data);
}

int32_t AuthSessionProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    return GetAuthMangerIf()->AuthSessionProcessAuthData(authSeq, data, len);
}

int32_t PostDeviceMessage(const AuthManager *auth, int32_t flagRelay, AuthLinkType type,
    const DeviceMessageParse *messageParse)
{
    return GetAuthMangerIf()->PostDeviceMessage(auth, flagRelay, type, messageParse);
}

int32_t AuthSetTcpKeepaliveOption(int32_t fd, ModeCycle cycle)
{
    return GetAuthMangerIf()->AuthSetTcpKeepaliveOption(fd, cycle);
}

bool IsDeviceMessagePacket(const AuthConnInfo *connInfo, const AuthDataHead *head,
    const uint8_t *data, bool isServer, DeviceMessageParse *messageParse)
{
    return GetAuthMangerIf()->IsDeviceMessagePacket(connInfo, head, data, isServer, messageParse);
}

int32_t AuthSessionProcessDevInfoDataByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len)
{
    return GetAuthMangerIf()->AuthSessionProcessDevInfoDataByConnId(connId, isServer, data, len);
}

int32_t AuthSessionProcessCloseAck(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    return GetAuthMangerIf()->AuthSessionProcessCloseAck(authSeq, data, len);
}

int32_t AuthSessionProcessCloseAckByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len)
{
    return GetAuthMangerIf()->AuthSessionProcessCloseAckByConnId(connId, isServer, data, len);
}

uint32_t AuthGetUkDecryptSize(uint32_t inLen)
{
    return GetAuthMangerIf()->AuthGetUkDecryptSize(inLen);
}

int32_t AuthDecryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    return GetAuthMangerIf()->AuthDecryptByUkId(ukId, inData, inLen, outData, outLen);
}

int32_t DecryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
    uint8_t **outData, uint32_t *outLen)
{
    return GetAuthMangerIf()->DecryptInner(list, type, inDataInfo, outData, outLen);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetAuthMangerIf()->LnnGetOnlineStateById(id, type);
}

int32_t AuthSessionProcessCancelAuthByConnId(uint64_t connId, bool isConnectServer, const uint8_t *data, uint32_t len)
{
    return GetAuthMangerIf()->AuthSessionProcessCancelAuthByConnId(connId, isConnectServer, data, len);
}

uint32_t ConnGetNewRequestId(ConnModule moduleId)
{
    return GetAuthMangerIf()->ConnGetNewRequestId(moduleId);
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    return GetAuthMangerIf()->LnnGetNetworkIdByUuid(uuid, buf, len);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetAuthMangerIf()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info)
{
    return GetAuthMangerIf()->LnnGetRemoteNumU32Info(networkId, key, info);
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return GetAuthMangerIf()->LnnGetRemoteStrInfo(networkId, key, info, len);
}

bool IsRemoteDeviceSupportBleGuide(const char *id, IdCategory type)
{
    return GetAuthMangerIf()->IsRemoteDeviceSupportBleGuide(id, type);
}

bool CheckActiveAuthConnection(const AuthConnInfo *connInfo)
{
    return GetAuthMangerIf()->CheckActiveAuthConnection(connInfo);
}

AuthLinkType ConvertToAuthLinkType(DiscoveryType type)
{
    return GetAuthMangerIf()->ConvertToAuthLinkType(type);
}

DiscoveryType ConvertToDiscoveryType(AuthLinkType type)
{
    return GetAuthMangerIf()->ConvertToDiscoveryType(type);
}

AuthLinkType GetSessionKeyTypeByIndex(const SessionKeyList *list, int32_t index)
{
    return GetAuthMangerIf()->GetSessionKeyTypeByIndex(list, index);
}

int32_t AuthCommonInit(void)
{
    return GetAuthMangerIf()->AuthCommonInit();
}

int32_t AuthConnInit(const AuthConnListener *listener)
{
    return GetAuthMangerIf()->AuthConnInit(listener);
}

void AuthCommonDeinit(void)
{
    return GetAuthMangerIf()->AuthCommonDeinit();
}

int32_t LnnInitModuleNotifyWithRetryAsync(uint32_t module, ModuleInitCallBack callback, uint32_t retryMax,
    uint32_t delay, bool isFirstDelay)
{
    return GetAuthMangerIf()->LnnInitModuleNotifyWithRetryAsync(module, callback, retryMax, delay, isFirstDelay);
}

void UnregTrustDataChangeListener(void)
{
    return GetAuthMangerIf()->UnregTrustDataChangeListener();
}

int32_t UnRegHichainSaStatusListener(void)
{
    return GetAuthMangerIf()->UnRegHichainSaStatusListener();
}

void ClearAuthRequest(void)
{
    return GetAuthMangerIf()->ClearAuthRequest();
}

void AuthConnDeinit(void)
{
    return GetAuthMangerIf()->AuthConnDeinit();
}

void AuthSessionFsmExit(void)
{
    return GetAuthMangerIf()->AuthSessionFsmExit();
}

void StopSessionKeyListening(int32_t fd)
{
    return GetAuthMangerIf()->StopSessionKeyListening(fd);
}

int32_t AuthSessionHandleDeviceDisconnected(uint64_t connId, bool isNeedDisconnect)
{
    return GetAuthMangerIf()->AuthSessionHandleDeviceDisconnected(connId, isNeedDisconnect);
}

bool RequireAuthLock(void)
{
    return GetAuthMangerIf()->RequireAuthLock();
}

void ReleaseAuthLock(void)
{
    return GetAuthMangerIf()->ReleaseAuthLock();
}

void UpdateFd(uint64_t *connId, int32_t id)
{
    return GetAuthMangerIf()->UpdateFd(connId, id);
}

const char *GetConnTypeStr(uint64_t connId)
{
    return GetAuthMangerIf()->GetConnTypeStr(connId);
}

uint32_t GetConnId(uint64_t connId)
{
    return GetAuthMangerIf()->GetConnId(connId);
}

int32_t FindAuthRequestByConnInfo(const AuthConnInfo *connInfo, AuthRequest *request)
{
    return GetAuthMangerIf()->FindAuthRequestByConnInfo(connInfo, request);
}

int32_t ConnectAuthDevice(uint32_t requestId, const AuthConnInfo *connInfo, ConnSideType sideType)
{
    return GetAuthMangerIf()->ConnectAuthDevice(requestId, connInfo, sideType);
}

int32_t AuthSessionProcessDevInfoData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    return GetAuthMangerIf()->AuthSessionProcessDevInfoData(authSeq, data, len);
}

int32_t GetFd(uint64_t connId)
{
    return GetAuthMangerIf()->GetFd(connId);
}

void LnnClearAuthExchangeUdidPacked(const char *networkId)
{
    return GetAuthMangerIf()->LnnClearAuthExchangeUdidPacked(networkId);
}

uint64_t GenConnId(int32_t connType, int32_t id)
{
    return GetAuthMangerIf()->GenConnId(connType, id);
}
}
} // namespace OHOS