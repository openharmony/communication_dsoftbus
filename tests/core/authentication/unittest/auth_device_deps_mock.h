/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef AUTH_DEVICE_DEPS_MOCK_H
#define AUTH_DEVICE_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "auth_common.h"
#include "auth_connection.h"
#include "auth_deviceprofile.h"
#include "auth_hichain.h"
#include "auth_manager.h"
#include "auth_request.h"
#include "auth_session_message.h"
#include "bus_center_manager.h"
#include "device_profile_listener.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_decision_db.h"
#include "lnn_distributed_net_ledger_common.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_map.h"
#include "lnn_net_builder.h"
#include "lnn_ohos_account_adapter.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "softbus_utils.h"

namespace OHOS {
class AuthDeviceDepsInterface {
public:
    AuthDeviceDepsInterface() {};
    virtual ~AuthDeviceDepsInterface() {};

    virtual AuthManager *GetAuthManagerByAuthId(int64_t authId) = 0;
    virtual void DelDupAuthManager(AuthManager *auth) = 0;
    virtual void RemoveNotPassedAuthManagerByUdid(const char *udid) = 0;
    virtual AuthManager *GetDeviceAuthManager(int64_t authSeq, const AuthSessionInfo *info,
        bool *isNewCreated, int64_t lastAuthSeq) = 0;
    virtual int64_t GetLatestIdByConnInfo(const AuthConnInfo *connInfo) = 0;
    virtual int64_t GetActiveAuthIdByConnInfo(const AuthConnInfo *connInfo, bool judgeTimeOut) = 0;
    virtual uint64_t GetCurrentTimeMsMock(void) = 0;
    virtual int64_t GenSeqMock(bool isServer) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t ConvertBytesToUpperCaseHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t EncryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
        uint8_t **outData, uint32_t *outLen) = 0;
    virtual int32_t EncryptData(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
        uint8_t *outData, uint32_t *outLen) = 0;
    virtual int32_t DecryptData(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
        uint8_t *outData, uint32_t *outLen) = 0;
    virtual uint32_t AuthGetDecryptSize(uint32_t inLen) = 0;
    virtual int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data) = 0;
    virtual int32_t ConnectAuthDevice(uint32_t requestId, const AuthConnInfo *connInfo, ConnSideType sideType) = 0;
    virtual void DisconnectAuthDevice(uint64_t *connId) = 0;
    virtual ConnSideType GetConnSideType(uint64_t connId) = 0;
    virtual uint32_t GetConnId(uint64_t connId) = 0;
    virtual bool CheckAuthConnInfoTypeMock(const AuthConnInfo *connInfo) = 0;
    virtual bool CheckAuthConnCallback(const AuthConnCallback *connCb) = 0;
    virtual bool CheckVerifyCallback(const AuthVerifyCallback *verifyCb) = 0;
    virtual bool CheckSessionKeyListExistType(const SessionKeyList *list, AuthLinkType type) = 0;
    virtual bool RequireAuthLockMock(void) = 0;
    virtual void ReleaseAuthLockMock(void) = 0;
    virtual uint32_t AddAuthRequest(const AuthRequest *request) = 0;
    virtual int32_t FindAndDelAuthRequestByConnInfo(uint32_t requestId, const AuthConnInfo *connInfo) = 0;
    virtual void DelAuthRequest(uint32_t requestId) = 0;
    virtual void LnnMapInit(Map *map) = 0;
    virtual int32_t LnnMapSet(Map *map, const char *key, const void *value, uint32_t valueSize) = 0;
    virtual void *LnnMapGet(const Map *map, const char *key) = 0;
    virtual int32_t LnnMapErase(Map *map, const char *key) = 0;
    virtual void LnnMapDelete(Map *map) = 0;
    virtual int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId) = 0;
    virtual int32_t JudgeDeviceTypeAndGetOsAccountIds(void) = 0;
    virtual void LnnHbOnTrustedRelationIncreased(int32_t groupType) = 0;
    virtual void LnnHbOnTrustedRelationReduced(void) = 0;
    virtual int32_t LnnInsertSpecificTrustedDevInfo(const char *udid) = 0;
    virtual int32_t LnnRequestLeaveSpecific(
        const char *networkId, ConnectionAddrType addrType, DeviceLeaveReason leaveReason) = 0;
    virtual void AuthRemoveDeviceKeyByUdidPacked(const char *udid) = 0;
    virtual int32_t AuthSessionHandleDeviceNotTrusted(const char *peerUdid) = 0;
    virtual bool DpHasAccessControlProfile(const char *udid, bool isSameAccount, int32_t userId) = 0;
    virtual void LnnDeleteLinkFinderInfo(const char *peerUdid) = 0;
    virtual int32_t RegTrustDataChangeListener(const TrustDataChangeListener *listener) = 0;
    virtual void SoftBusSleepMsMock(unsigned int ms) = 0;
    virtual int32_t RegisterToDp(DeviceProfileChangeListener *deviceProfilePara) = 0;
    virtual int32_t InitDbListDelay(void) = 0;
    virtual void SoftbusHitraceStart(uint32_t flags, uint64_t chainId) = 0;
    virtual void SoftbusHitraceStop(void) = 0;
};

class AuthDeviceDepsInterfaceMock : public AuthDeviceDepsInterface {
public:
    AuthDeviceDepsInterfaceMock();
    ~AuthDeviceDepsInterfaceMock() override;

    MOCK_METHOD1(GetAuthManagerByAuthId, AuthManager *(int64_t));
    MOCK_METHOD1(DelDupAuthManager, void(AuthManager *));
    MOCK_METHOD1(RemoveNotPassedAuthManagerByUdid, void(const char *));
    MOCK_METHOD4(GetDeviceAuthManager, AuthManager *(int64_t, const AuthSessionInfo *, bool *, int64_t));
    MOCK_METHOD1(GetLatestIdByConnInfo, int64_t(const AuthConnInfo *));
    MOCK_METHOD2(GetActiveAuthIdByConnInfo, int64_t(const AuthConnInfo *, bool));
    MOCK_METHOD0(GetCurrentTimeMsMock, uint64_t(void));
    MOCK_METHOD1(GenSeqMock, int64_t(bool));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD4(ConvertBytesToUpperCaseHexString,
        int32_t(char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD5(EncryptInner,
        int32_t(const SessionKeyList *, AuthLinkType, const InDataInfo *, uint8_t **, uint32_t *));
    MOCK_METHOD5(EncryptData, int32_t(const SessionKeyList *, AuthLinkType, const InDataInfo *, uint8_t *, uint32_t *));
    MOCK_METHOD5(DecryptData, int32_t(const SessionKeyList *, AuthLinkType, const InDataInfo *, uint8_t *, uint32_t *));
    MOCK_METHOD1(AuthGetDecryptSize, uint32_t(uint32_t));
    MOCK_METHOD4(PostAuthData, int32_t(uint64_t, bool, const AuthDataHead *, const uint8_t *));
    MOCK_METHOD3(ConnectAuthDevice, int32_t(uint32_t, const AuthConnInfo *, ConnSideType));
    MOCK_METHOD1(DisconnectAuthDevice, void(uint64_t *));
    MOCK_METHOD1(GetConnSideType, ConnSideType(uint64_t));
    MOCK_METHOD1(GetConnId, uint32_t(uint64_t));
    MOCK_METHOD1(CheckAuthConnInfoTypeMock, bool(const AuthConnInfo *));
    MOCK_METHOD1(CheckAuthConnCallback, bool(const AuthConnCallback *));
    MOCK_METHOD1(CheckVerifyCallback, bool(const AuthVerifyCallback *));
    MOCK_METHOD2(CheckSessionKeyListExistType, bool(const SessionKeyList *, AuthLinkType));
    MOCK_METHOD0(RequireAuthLockMock, bool(void));
    MOCK_METHOD0(ReleaseAuthLockMock, void(void));
    MOCK_METHOD1(AddAuthRequest, uint32_t(const AuthRequest *));
    MOCK_METHOD2(FindAndDelAuthRequestByConnInfo, int32_t(uint32_t, const AuthConnInfo *));
    MOCK_METHOD1(DelAuthRequest, void(uint32_t));
    MOCK_METHOD1(LnnMapInit, void(Map *));
    MOCK_METHOD4(LnnMapSet, int32_t(Map *, const char *, const void *, uint32_t));
    MOCK_METHOD2(LnnMapGet, void *(const Map *, const char *));
    MOCK_METHOD2(LnnMapErase, int32_t(Map *, const char *));
    MOCK_METHOD1(LnnMapDelete, void(Map *));
    MOCK_METHOD3(LnnGetNetworkIdByUdid, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD2(LnnGetRemoteNodeInfoByKey, int32_t(const char *, NodeInfo *));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey, char *, uint32_t));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey, int32_t *));
    MOCK_METHOD2(LnnDeleteSpecificTrustedDevInfo, int32_t(const char *, int32_t));
    MOCK_METHOD0(JudgeDeviceTypeAndGetOsAccountIds, int32_t(void));
    MOCK_METHOD1(LnnHbOnTrustedRelationIncreased, void(int32_t));
    MOCK_METHOD0(LnnHbOnTrustedRelationReduced, void(void));
    MOCK_METHOD1(LnnInsertSpecificTrustedDevInfo, int32_t(const char *));
    MOCK_METHOD3(LnnRequestLeaveSpecific, int32_t(const char *, ConnectionAddrType, DeviceLeaveReason));
    MOCK_METHOD1(AuthRemoveDeviceKeyByUdidPacked, void(const char *));
    MOCK_METHOD1(AuthSessionHandleDeviceNotTrusted, int32_t(const char *));
    MOCK_METHOD3(DpHasAccessControlProfile, bool(const char *, bool, int32_t));
    MOCK_METHOD1(LnnDeleteLinkFinderInfo, void(const char *));
    MOCK_METHOD1(RegTrustDataChangeListener, int32_t(const TrustDataChangeListener *));
    MOCK_METHOD1(SoftBusSleepMsMock, void(unsigned int));
    MOCK_METHOD1(RegisterToDp, int32_t(DeviceProfileChangeListener *));
    MOCK_METHOD0(InitDbListDelay, int32_t(void));
    MOCK_METHOD2(SoftbusHitraceStart, void(uint32_t, uint64_t));
    MOCK_METHOD0(SoftbusHitraceStop, void(void));
};
} // namespace OHOS
#endif // AUTH_DEVICE_DEPS_MOCK_H
