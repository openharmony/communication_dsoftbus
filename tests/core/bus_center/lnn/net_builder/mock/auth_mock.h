/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_MOCK_H
#define AUTH_MOCK_H

#include <gmock/gmock.h>

#include "auth_interface.h"

namespace OHOS {
class AuthInterface {
public:
    AuthInterface() {};
    virtual ~AuthInterface() {};

    virtual void AuthHandleLeaveLNN(AuthHandle authHandle) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual int32_t AuthStartVerify(const AuthConnInfo *connInfo, AuthVerifyParam *authVerifyParam,
        const AuthVerifyCallback *callback) = 0;
    virtual int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version) = 0;
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
    virtual int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener) = 0;
    virtual void UnregAuthTransListener(int32_t module) = 0;
    virtual int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo) = 0;
    virtual int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta) = 0;
    virtual int32_t AuthFlushDevice(const char *uuid) = 0;
    virtual int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle) = 0;
    virtual int32_t AuthStartConnVerify(const AuthConnInfo *connInfo, uint32_t requestId,
        const AuthConnCallback *connCallback, AuthVerifyModule module, bool isFastAuth) = 0;
    virtual int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
        int32_t callingPid, const AuthVerifyCallback *callBack) = 0;
    virtual void AuthMetaReleaseVerify(int64_t authId) = 0;
    virtual void AuthServerDeathCallback(const char *pkgName, int32_t pid) = 0;
    virtual int32_t RegGroupChangeListener(const GroupChangeListener *listener) = 0;
    virtual void UnregGroupChangeListener(void) = 0;
    virtual bool AuthIsPotentialTrusted(const DeviceInfo *device, bool isOnlyPointToPoint) = 0;
    virtual bool IsAuthHasTrustedRelation(void) = 0;
    virtual bool IsSameAccountDevice(const DeviceInfo *device) = 0;
    virtual bool AuthHasSameAccountGroup(void) = 0;

    virtual int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port) = 0;
    virtual void AuthStopListening(AuthLinkType type) = 0;
    virtual int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip, int32_t port,
        ListenerModule *moduleId) = 0;
    virtual void AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId) = 0;

    virtual int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback,
        bool isMeta) = 0;
    virtual void AuthCloseConn(AuthHandle authHandle) = 0;
    virtual int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetConnInfoByType(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *seqList, uint32_t num) = 0;
    virtual int32_t AuthGetLatestAuthSeqListByType(const char *udid, int64_t *seqList, uint64_t *authVerifyTime,
        DiscoveryType type) = 0;
    virtual void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle) = 0;
    virtual int32_t AuthGetAuthHandleByIndex(const AuthConnInfo *connInfo, bool isServer, int32_t index,
        AuthHandle *authHandle) = 0;
    virtual int64_t AuthGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer, bool isMeta) = 0;

    virtual uint32_t AuthGetEncryptSize(int64_t authId, uint32_t inLen) = 0;
    virtual uint32_t AuthGetDecryptSize(uint32_t inLen) = 0;
    virtual int32_t AuthEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
        uint32_t *outLen) = 0;
    virtual int32_t AuthDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
        uint32_t *outLen) = 0;
    virtual int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac) = 0;

    virtual int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo) = 0;
    virtual int32_t AuthGetServerSide(int64_t authId, bool *isServer) = 0;
    virtual int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth) = 0;
    virtual uint32_t AuthGetGroupType(const char *udid, const char *uuid) = 0;
    virtual bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit) = 0;
    virtual void AuthRemoveAuthManagerByAuthHandle(AuthHandle authHandle) = 0;

    virtual int32_t AuthCheckSessionKeyValidByConnInfo(const char *networkId, const AuthConnInfo *connInfo) = 0;
    virtual int32_t AuthCheckSessionKeyValidByAuthHandle(const AuthHandle *authHandle) = 0;
    virtual int32_t AuthInit(void) = 0;
    virtual void AuthDeinit(void) = 0;
    virtual int32_t AuthRestoreAuthManager(const char *udidHash,
        const AuthConnInfo *connInfo, uint32_t requestId, NodeInfo *nodeInfo, int64_t *authId) = 0;
    virtual int32_t AuthCheckMetaExist(const AuthConnInfo *connInfo, bool *isExist) = 0;
};

class AuthInterfaceMock : public AuthInterface {
public:
    AuthInterfaceMock();
    ~AuthInterfaceMock() override;
    MOCK_METHOD(void, AuthHandleLeaveLNN, (AuthHandle), (override));
    MOCK_METHOD(uint32_t, AuthGenRequestId, (), (override));
    MOCK_METHOD(int32_t, AuthStartVerify,
        (const AuthConnInfo *, AuthVerifyParam *, const AuthVerifyCallback *), (override));
    MOCK_METHOD(int32_t, AuthGetVersion, (int64_t, SoftBusVersion *), (override));
    MOCK_METHOD(int32_t, AuthGetDeviceUuid, (int64_t, char *, uint16_t), (override));

    MOCK_METHOD2(RegAuthTransListener, int32_t(int32_t, const AuthTransListener *));
    MOCK_METHOD1(UnregAuthTransListener, void(int32_t));
    MOCK_METHOD2(AuthPostTransData, int32_t(AuthHandle, const AuthTransData *));
    MOCK_METHOD3(AuthGetIdByConnInfo, int64_t(const AuthConnInfo *, bool, bool));
    MOCK_METHOD1(AuthFlushDevice, int32_t(const char *));
    MOCK_METHOD2(AuthSendKeepaliveOption, int32_t(const char *, ModeCycle));
    MOCK_METHOD5(AuthStartConnVerify, int32_t(const AuthConnInfo *, uint32_t, const AuthConnCallback *,
        AuthVerifyModule, bool));
    MOCK_METHOD5(AuthMetaStartVerify, int32_t(uint32_t, const AuthKeyInfo *, uint32_t, int32_t
        const AuthVerifyCallback *));
    MOCK_METHOD1(AuthMetaReleaseVerify, void(int64_t));
    MOCK_METHOD2(AuthServerDeathCallback, void(const char *, int32_t));
    MOCK_METHOD1(RegGroupChangeListener, int32_t(const GroupChangeListener *));
    MOCK_METHOD0(UnregGroupChangeListener, void());
    MOCK_METHOD2(AuthIsPotentialTrusted, bool(const DeviceInfo *, bool));
    MOCK_METHOD0(IsAuthHasTrustedRelation, bool());
    MOCK_METHOD1(IsSameAccountDevice, bool(const DeviceInfo *));
    MOCK_METHOD0(AuthHasSameAccountGroup, bool());

    MOCK_METHOD3(AuthStartListening, int32_t(AuthLinkType, const char *, int32_t));
    MOCK_METHOD1(AuthStopListening, void(AuthLinkType));
    MOCK_METHOD4(AuthStartListeningForWifiDirect, int32_t(AuthLinkType, const char *, int32_t, ListenerModule *));
    MOCK_METHOD2(AuthStopListeningForWifiDirect, void(AuthLinkType, ListenerModule));

    MOCK_METHOD4(AuthOpenConn, int32_t(const AuthConnInfo *, uint32_t, const AuthConnCallback *, bool));
    MOCK_METHOD1(AuthCloseConn, void(AuthHandle));
    MOCK_METHOD3(AuthGetPreferConnInfo, int32_t(const char *, AuthConnInfo *, bool));
    MOCK_METHOD4(AuthGetConnInfoByType, int32_t(const char *, AuthLinkType, AuthConnInfo *, bool));
    MOCK_METHOD3(AuthGetP2pConnInfo, int32_t(const char *, AuthConnInfo *, bool));
    MOCK_METHOD3(AuthGetHmlConnInfo, int32_t(const char *, AuthConnInfo *, bool));
    MOCK_METHOD3(AuthGetLatestAuthSeqList, int32_t(const char *, int64_t *, uint32_t));
    MOCK_METHOD4(AuthGetLatestAuthSeqListByType, int32_t(const char *, int64_t *, uint64_t *, DiscoveryType));
    MOCK_METHOD4(AuthGetLatestIdByUuid, void(const char *, AuthLinkType, bool, AuthHandle *));
    MOCK_METHOD4(AuthGetAuthHandleByIndex, int32_t(const AuthConnInfo *, bool, int32_t, AuthHandle *));
    MOCK_METHOD3(AuthGetIdByUuid, int64_t(const char *, bool, bool));

    MOCK_METHOD2(AuthGetEncryptSize, uint32_t(int64_t, uint32_t));
    MOCK_METHOD1(AuthGetDecryptSize, uint32_t(uint32_t));
    MOCK_METHOD5(AuthEncrypt, int32_t(AuthHandle *, const uint8_t *, uint32_t, uint8_t *, uint32_t *));
    MOCK_METHOD5(AuthDecrypt, int32_t(AuthHandle *, const uint8_t *, uint32_t, uint8_t *, uint32_t *));
    MOCK_METHOD2(AuthSetP2pMac, int32_t(int64_t, const char *));

    MOCK_METHOD2(AuthGetConnInfo, int32_t(AuthHandle, AuthConnInfo *));
    MOCK_METHOD2(AuthGetServerSide, int32_t(int64_t, bool *));
    MOCK_METHOD2(AuthGetMetaType, int32_t(int64_t, bool *));
    MOCK_METHOD2(AuthGetGroupType, uint32_t(const char *, const char *));
    MOCK_METHOD2(IsSupportFeatureByCapaBit, bool(uint32_t, AuthCapability));
    MOCK_METHOD1(AuthRemoveAuthManagerByAuthHandle, void(AuthHandle));

    MOCK_METHOD2(AuthCheckSessionKeyValidByConnInfo, int32_t(const char *, const AuthConnInfo *));
    MOCK_METHOD1(AuthCheckSessionKeyValidByAuthHandle, bool(const AuthHandle *));
    MOCK_METHOD0(AuthInit, int32_t(void));
    MOCK_METHOD0(AuthDeinit, void(void));
    MOCK_METHOD5(AuthRestoreAuthManager, int32_t(const char *, const AuthConnInfo *, uint32_t, NodeInfo *, int64_t *));
    MOCK_METHOD2(AuthCheckMetaExist, int32_t(const AuthConnInfo *, bool *));
};
} // namespace OHOS
#endif // AUTH_MOCK_H