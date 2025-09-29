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

#ifndef AUTH_MANAGER_DEPS_MOCK_H
#define AUTH_MANAGER_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_common.h"
#include "auth_connection.h"
#include "auth_device_common_key.h"
#include "auth_device.h"
#include "auth_hichain.h"
#include "auth_interface.h"
#include "auth_normalize_request.h"
#include "auth_request.h"
#include "auth_session_fsm.h"
#include "auth_session_key.h"
#include "auth_session_message.h"
#include "auth_tcp_connection.h"
#include "auth_uk_manager.h"
#include "bus_center_manager.h"
#include "lnn_connection_fsm.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_init_monitor.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_crypto.h"
#include "softbus_conn_interface.h"

namespace OHOS {
class AuthManagerInterface {
public:
    AuthManagerInterface() {};
    virtual ~AuthManagerInterface() {};

    virtual bool CheckAuthConnInfoType(const AuthConnInfo *connInfo) = 0;
    virtual void InitSessionKeyList(SessionKeyList *list) = 0;
    virtual const char *GetAuthSideStr(bool isServer) = 0;
    virtual uint8_t *DupMemBuffer(const uint8_t *buf, uint32_t size) = 0;
    virtual int32_t DupSessionKeyList(const SessionKeyList *srcList, SessionKeyList *dstList) = 0;
    virtual void DestroySessionKeyList(SessionKeyList *list) = 0;
    virtual void ClearSessionkeyByAuthLinkType(int64_t authId, SessionKeyList *list, AuthLinkType type) = 0;
    virtual void CancelUpdateSessionKey(int64_t authId) = 0;
    virtual bool CompareConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash) = 0;
    virtual int32_t GetConnType(uint64_t connId) = 0;
    virtual void RemoveSessionkeyByIndex(SessionKeyList *list, int32_t index, AuthLinkType type) = 0;
    virtual bool CheckSessionKeyListExistType(const SessionKeyList *list, AuthLinkType type) = 0;
    virtual void AuthRemoveDeviceKeyByUdid(const char *udidOrHash) = 0;
    virtual int32_t LnnNotifyEmptySessionKey(int64_t authId) = 0;
    virtual int32_t LnnNotifyLeaveLnnByAuthHandle(AuthHandle *authHandle) = 0;
    virtual void PrintAuthConnInfo(const AuthConnInfo *connInfo) = 0;
    virtual uint64_t GetLatestAvailableSessionKeyTime(const SessionKeyList *list, AuthLinkType type) = 0;
    virtual uint64_t GetCurrentTimeMs(void) = 0;
    virtual int32_t SetSessionKeyAuthLinkType(const SessionKeyList *list, int32_t index, AuthLinkType type) = 0;
    virtual int32_t AddSessionKey(SessionKeyList *list, int32_t index, const SessionKey *key,
        AuthLinkType type, bool isOldKey) = 0;
    virtual AuthFsm *GetAuthFsmByConnId(uint64_t connId, bool isServer, bool isConnectSide) = 0;
    virtual void DisconnectAuthDevice(uint64_t *connId) = 0;
    virtual int32_t ClearOldKey(const SessionKeyList *list, AuthLinkType type) = 0;
    virtual int32_t SetSessionKeyAvailable(SessionKeyList *list, int32_t index) = 0;
    virtual int32_t GetSessionKeyByIndex(const SessionKeyList *list, int32_t index,
        AuthLinkType type, SessionKey *key) = 0;
    virtual void ScheduleUpdateSessionKey(AuthHandle authHandle, uint64_t delatMs) = 0;
    virtual int64_t GenSeq(bool isServer) = 0;
    virtual int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request) = 0;
    virtual void AuthNotifyDeviceVerifyPassed(AuthHandle authHandle, const NodeInfo *nodeInfo) = 0;
    virtual bool CheckAuthConnCallback(const AuthConnCallback *connCb) = 0;
    virtual void PerformAuthConnCallback(uint32_t requestId, int32_t result, int64_t authId) = 0;
    virtual void DelAuthRequest(uint32_t requestId) = 0;
    virtual int32_t AuthStartReconnectDevice(AuthHandle authHandle, const AuthConnInfo *connInfo,
        uint32_t requestId, const AuthConnCallback *connCb) = 0;
    virtual void PerformVerifyCallback(uint32_t requestId, int32_t result, AuthHandle authHandle,
        const NodeInfo *info) = 0;
    virtual int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data) = 0;
    virtual void DelAuthNormalizeRequest(int64_t authSeq) = 0;
    virtual void UpdateAuthDevicePriority(uint64_t connId) = 0;
    virtual bool LnnSetDlPtk(const char *networkId, const char *remotePtk) = 0;
    virtual int32_t GetIsExchangeUdidByNetworkId(const char *networkId, bool *isExchangeUdid) = 0;
    virtual void LnnClearAuthExchangeUdid(const char *networkId) = 0;
    virtual void AuthNotifyDeviceDisconnect(AuthHandle authHandle) = 0;
    virtual void AuthAddNodeToLimitMap(const char *udid, int32_t reason) = 0;
    virtual int32_t PostAuthEvent(EventType event, EventHandler handler,
        const void *obj, uint32_t size, uint64_t delayMs) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit) = 0;
    virtual void AuthDeleteLimitMap(const char *udidHash) = 0;
    virtual int32_t AuthSessionStartAuth(const AuthParam *authParam, const AuthConnInfo *connInfo,
        const DeviceKeyId *deviceKeyId) = 0;
    virtual void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo) = 0;
    virtual int32_t AuthSessionProcessDevIdData(int64_t authSeq, const uint8_t *data, uint32_t len) = 0;
    virtual bool GetConfigSupportAsServer(void) = 0;
    virtual void HandleRepeatDeviceIdDataDelay(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
        const AuthDataHead *head, const uint8_t *data) = 0;
    virtual int32_t AuthSessionProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len) = 0;
    virtual int32_t PostDeviceMessage(const AuthManager *auth, int32_t flagRelay, AuthLinkType type,
        const DeviceMessageParse *messageParse) = 0;
    virtual int32_t AuthSetTcpKeepaliveOption(int32_t fd, ModeCycle cycle) = 0;
    virtual bool IsDeviceMessagePacket(const AuthConnInfo *connInfo, const AuthDataHead *head,
        const uint8_t *data, bool isServer, DeviceMessageParse *messageParse) = 0;
    virtual int32_t AuthSessionProcessDevInfoDataByConnId(uint64_t connId, bool isServer,
        const uint8_t *data, uint32_t len) = 0;
    virtual int32_t AuthSessionProcessCloseAck(int64_t authSeq, const uint8_t *data, uint32_t len) = 0;
    virtual int32_t AuthSessionProcessCloseAckByConnId(uint64_t connId, bool isServer,
        const uint8_t *data, uint32_t len) = 0;
    virtual uint32_t AuthGetUkDecryptSize(uint32_t inLen) = 0;
    virtual int32_t AuthDecryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen,
        uint8_t *outData, uint32_t *outLen) = 0;
    virtual int32_t DecryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
        uint8_t **outData, uint32_t *outLen) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t AuthSessionProcessCancelAuthByConnId(uint64_t connId, bool isConnectServer,
        const uint8_t *data, uint32_t len) = 0;
    virtual uint32_t ConnGetNewRequestId(ConnModule moduleId) = 0;
    virtual int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len) = 0;
    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual bool IsRemoteDeviceSupportBleGuide(const char *id, IdCategory type) = 0;
    virtual bool CheckActiveAuthConnection(const AuthConnInfo *connInfo) = 0;
    virtual AuthLinkType ConvertToAuthLinkType(DiscoveryType type) = 0;
    virtual DiscoveryType ConvertToDiscoveryType(AuthLinkType type) = 0;
    virtual AuthLinkType GetSessionKeyTypeByIndex(const SessionKeyList *list, int32_t index) = 0;
    virtual int32_t AuthCommonInit(void) = 0;
    virtual int32_t AuthConnInit(const AuthConnListener *listener) = 0;
    virtual void AuthCommonDeinit(void) = 0;
    virtual int32_t LnnInitModuleNotifyWithRetryAsync(uint32_t module, ModuleInitCallBack callback,
        uint32_t retryMax, uint32_t delay, bool isFirstDelay) = 0;
    virtual void UnregTrustDataChangeListener(void) = 0;
    virtual int32_t UnRegHichainSaStatusListener(void) = 0;
    virtual void ClearAuthRequest(void) = 0;
    virtual void AuthConnDeinit(void) = 0;
    virtual void AuthSessionFsmExit(void) = 0;
    virtual void StopSessionKeyListening(int32_t fd) = 0;
    virtual int32_t AuthSessionHandleDeviceDisconnected(uint64_t connId, bool isNeedDisconnect) = 0;
    virtual bool RequireAuthLock(void) = 0;
    virtual void ReleaseAuthLock(void) = 0;
    virtual void UpdateFd(uint64_t *connId, int32_t id) = 0;
    virtual const char *GetConnTypeStr(uint64_t connId) = 0;
    virtual uint32_t GetConnId(uint64_t connId) = 0;
    virtual int32_t FindAuthRequestByConnInfo(const AuthConnInfo *connInfo, AuthRequest *request) = 0;
    virtual int32_t ConnectAuthDevice(uint32_t requestId, const AuthConnInfo *connInfo, ConnSideType sideType) = 0;
};
class AuthManagerInterfaceMock : public AuthManagerInterface {
public:
    AuthManagerInterfaceMock();
    ~AuthManagerInterfaceMock() override;
    
    MOCK_METHOD1(CheckAuthConnInfoType, bool (const AuthConnInfo *));
    MOCK_METHOD1(InitSessionKeyList, void (SessionKeyList *));
    MOCK_METHOD1(GetAuthSideStr, const char * (bool));
    MOCK_METHOD2(DupMemBuffer, uint8_t * (const uint8_t *, uint32_t));
    MOCK_METHOD2(DupSessionKeyList, int32_t (const SessionKeyList *, SessionKeyList *));
    MOCK_METHOD1(DestroySessionKeyList, void (SessionKeyList *));
    MOCK_METHOD3(ClearSessionkeyByAuthLinkType, void (int64_t, SessionKeyList *, AuthLinkType));
    MOCK_METHOD1(CancelUpdateSessionKey, void (int64_t));
    MOCK_METHOD3(CompareConnInfo, bool (const AuthConnInfo *, const AuthConnInfo *, bool));
    MOCK_METHOD1(GetConnType, int32_t (uint64_t));
    MOCK_METHOD3(RemoveSessionkeyByIndex, void (SessionKeyList *, int32_t, AuthLinkType));
    MOCK_METHOD2(CheckSessionKeyListExistType, bool (const SessionKeyList *, AuthLinkType));
    MOCK_METHOD1(AuthRemoveDeviceKeyByUdid, void (const char *));
    MOCK_METHOD1(LnnNotifyEmptySessionKey, int32_t (int64_t));
    MOCK_METHOD1(LnnNotifyLeaveLnnByAuthHandle, int32_t (AuthHandle *));
    MOCK_METHOD1(PrintAuthConnInfo, void (const AuthConnInfo *));
    MOCK_METHOD2(GetLatestAvailableSessionKeyTime, uint64_t (const SessionKeyList *, AuthLinkType));
    MOCK_METHOD0(GetCurrentTimeMs, uint64_t (void));
    MOCK_METHOD3(SetSessionKeyAuthLinkType, int32_t (const SessionKeyList *, int32_t, AuthLinkType));
    MOCK_METHOD5(AddSessionKey, int32_t (SessionKeyList *, int32_t, const SessionKey *, AuthLinkType, bool));
    MOCK_METHOD3(GetAuthFsmByConnId, AuthFsm * (uint64_t, bool, bool));
    MOCK_METHOD1(DisconnectAuthDevice, void (uint64_t *));
    MOCK_METHOD2(ClearOldKey, int32_t (const SessionKeyList *, AuthLinkType));
    MOCK_METHOD2(SetSessionKeyAvailable, int32_t (SessionKeyList *, int32_t));
    MOCK_METHOD4(GetSessionKeyByIndex, int32_t (const SessionKeyList *, int32_t, AuthLinkType, SessionKey *));
    MOCK_METHOD2(ScheduleUpdateSessionKey, void (AuthHandle, uint64_t));
    MOCK_METHOD1(GenSeq, int64_t (bool));
    MOCK_METHOD2(GetAuthRequest, int32_t (uint32_t, AuthRequest *));
    MOCK_METHOD2(AuthNotifyDeviceVerifyPassed, void (AuthHandle, const NodeInfo *));
    MOCK_METHOD1(CheckAuthConnCallback, bool (const AuthConnCallback *));
    MOCK_METHOD3(PerformAuthConnCallback, void (uint32_t, int32_t, int64_t));
    MOCK_METHOD1(DelAuthRequest, void (uint32_t));
    MOCK_METHOD4(AuthStartReconnectDevice, int32_t (AuthHandle, const AuthConnInfo *,
        uint32_t, const AuthConnCallback *));
    MOCK_METHOD4(PerformVerifyCallback, void (uint32_t, int32_t, AuthHandle, const NodeInfo *));
    MOCK_METHOD4(PostAuthData, int32_t (uint64_t, bool, const AuthDataHead *, const uint8_t *));
    MOCK_METHOD1(DelAuthNormalizeRequest, void (int64_t));
    MOCK_METHOD1(UpdateAuthDevicePriority, void (uint64_t));
    MOCK_METHOD2(LnnSetDlPtk, bool (const char *, const char *));
    MOCK_METHOD2(GetIsExchangeUdidByNetworkId, int32_t (const char *, bool *));
    MOCK_METHOD1(LnnClearAuthExchangeUdid, void (const char *));
    MOCK_METHOD1(AuthNotifyDeviceDisconnect, void (AuthHandle));
    MOCK_METHOD2(AuthAddNodeToLimitMap, void (const char *, int32_t));
    MOCK_METHOD5(PostAuthEvent, int32_t (EventType, EventHandler, const void *, uint32_t, uint64_t));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t (InfoKey, uint64_t *));
    MOCK_METHOD2(IsFeatureSupport, bool (uint64_t, FeatureCapability));
    MOCK_METHOD1(AuthDeleteLimitMap, void (const char *));
    MOCK_METHOD3(AuthSessionStartAuth, int32_t (const AuthParam *, const AuthConnInfo *, const DeviceKeyId *));
    MOCK_METHOD1(GetLnnTriggerInfo, void (LnnTriggerInfo *));
    MOCK_METHOD3(AuthSessionProcessDevIdData, int32_t (int64_t, const uint8_t *, uint32_t));
    MOCK_METHOD0(GetConfigSupportAsServer, bool (void));
    MOCK_METHOD5(HandleRepeatDeviceIdDataDelay, void (uint64_t, const AuthConnInfo *, bool,
        const AuthDataHead *, const uint8_t *));
    MOCK_METHOD3(AuthSessionProcessAuthData, int32_t (int64_t, const uint8_t *, uint32_t));
    MOCK_METHOD4(PostDeviceMessage, int32_t (const AuthManager *, int32_t, AuthLinkType, const DeviceMessageParse *));
    MOCK_METHOD2(AuthSetTcpKeepaliveOption, int32_t (int32_t, ModeCycle));
    MOCK_METHOD5(IsDeviceMessagePacket, bool (const AuthConnInfo *, const AuthDataHead *,
        const uint8_t *, bool, DeviceMessageParse *));
    MOCK_METHOD4(AuthSessionProcessDevInfoDataByConnId, int32_t (uint64_t, bool, const uint8_t *, uint32_t));
    MOCK_METHOD3(AuthSessionProcessCloseAck, int32_t (int64_t, const uint8_t *, uint32_t));
    MOCK_METHOD4(AuthSessionProcessCloseAckByConnId, int32_t (uint64_t, bool, const uint8_t *, uint32_t));
    MOCK_METHOD1(AuthGetUkDecryptSize, uint32_t (uint32_t));
    MOCK_METHOD5(AuthDecryptByUkId, int32_t (int32_t, const uint8_t *, uint32_t, uint8_t *, uint32_t *));
    MOCK_METHOD5(DecryptInner, int32_t (const SessionKeyList *, AuthLinkType,
        const InDataInfo *, uint8_t **, uint32_t *));
    MOCK_METHOD2(LnnGetOnlineStateById, bool (const char *, IdCategory));
    MOCK_METHOD4(AuthSessionProcessCancelAuthByConnId, int32_t (uint64_t, bool, const uint8_t *, uint32_t));
    MOCK_METHOD1(ConnGetNewRequestId, uint32_t (ConnModule));
    MOCK_METHOD3(LnnGetNetworkIdByUuid, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t (InfoKey, uint32_t *));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t (const char *, InfoKey, uint32_t *));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char *, InfoKey, char *, uint32_t));
    MOCK_METHOD2(IsRemoteDeviceSupportBleGuide, bool (const char *, IdCategory));
    MOCK_METHOD1(CheckActiveAuthConnection, bool (const AuthConnInfo *));
    MOCK_METHOD1(ConvertToAuthLinkType, AuthLinkType (DiscoveryType));
    MOCK_METHOD1(ConvertToDiscoveryType, DiscoveryType (AuthLinkType));
    MOCK_METHOD2(GetSessionKeyTypeByIndex, AuthLinkType (const SessionKeyList *, int32_t));
    MOCK_METHOD0(AuthCommonInit, int32_t (void));
    MOCK_METHOD1(AuthConnInit, int32_t (const AuthConnListener *));
    MOCK_METHOD0(AuthCommonDeinit, void (void));
    MOCK_METHOD5(LnnInitModuleNotifyWithRetryAsync, int32_t (uint32_t, ModuleInitCallBack, uint32_t, uint32_t, bool));
    MOCK_METHOD0(UnregTrustDataChangeListener, void (void));
    MOCK_METHOD0(UnRegHichainSaStatusListener, int32_t (void));
    MOCK_METHOD0(ClearAuthRequest, void (void));
    MOCK_METHOD0(AuthConnDeinit, void (void));
    MOCK_METHOD0(AuthSessionFsmExit, void (void));
    MOCK_METHOD1(StopSessionKeyListening, void (int32_t));
    MOCK_METHOD2(AuthSessionHandleDeviceDisconnected, int32_t (uint64_t, bool));
    MOCK_METHOD0(RequireAuthLock, bool (void));
    MOCK_METHOD0(ReleaseAuthLock, void (void));
    MOCK_METHOD2(UpdateFd, void (uint64_t *, int32_t));
    MOCK_METHOD1(GetConnTypeStr, const char * (uint64_t));
    MOCK_METHOD1(GetConnId, uint32_t (uint64_t));
    MOCK_METHOD2(FindAuthRequestByConnInfo, int32_t (const AuthConnInfo *, AuthRequest *));
    MOCK_METHOD3(ConnectAuthDevice, int32_t (uint32_t, const AuthConnInfo *, ConnSideType));
};
} // namespace OHOS
#endif // AUTH_MANAGER_DEPS_MOCK_H