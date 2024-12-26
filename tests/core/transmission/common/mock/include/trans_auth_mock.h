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

#ifndef TRANS_AUTH_MOCK_H
#define TRANS_AUTH_MOCK_H

#include <gmock/gmock.h>

#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "lnn_lane_interface.h"

namespace OHOS {
class TransAuthInterface {
public:
    TransAuthInterface() {};
    virtual ~TransAuthInterface() {};

    virtual int32_t AuthInit(void) = 0;
    virtual void AuthDeinit(void) = 0;

    virtual int32_t RegAuthVerifyListener(const AuthVerifyListener *listener) = 0;
    virtual void UnregAuthVerifyListener(void) = 0;
    virtual int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener) = 0;
    virtual void UnregAuthTransListener(int32_t module) = 0;
    virtual int32_t RegGroupChangeListener(const GroupChangeListener *listener) = 0;
    virtual void UnregGroupChangeListener(void) = 0;

    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual int32_t AuthFlushDevice(const char *uuid) = 0;
    virtual void AuthHandleLeaveLNN(AuthHandle authHandle) = 0;

    virtual int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port) = 0;
    virtual void AuthStopListening(AuthLinkType type) = 0;

    virtual int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId,
        const AuthConnCallback *callback, bool isMeta) = 0;
    virtual void AuthCloseConn(AuthHandle authHandle) = 0;
    virtual int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo) = 0;
    virtual int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;

    virtual void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle) = 0;
    virtual int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta) = 0;
    virtual int64_t AuthGetIdByP2pMac(const char *p2pMac, AuthLinkType type, bool isServer, bool isMeta) = 0;

    virtual uint32_t AuthGetEncryptSize(int64_t authId, uint32_t inLen) = 0;
    virtual uint32_t AuthGetDecryptSize(uint32_t inLen) = 0;

    virtual int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac) = 0;
    virtual int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo) = 0;
    virtual int32_t AuthGetServerSide(int64_t authId, bool *isServer) = 0;
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
    virtual int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version) = 0;
    virtual int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth) = 0;

    virtual int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
        int32_t callingPid, const AuthVerifyCallback *callBack) = 0;
    virtual void AuthMetaReleaseVerify(int64_t authId) = 0;

    virtual int32_t AuthEncrypt(AuthHandle *authHandle, const uint8_t *inData,
        uint32_t inLen, uint8_t *outData, uint32_t *outLen) = 0;
    virtual int32_t AuthDecrypt(AuthHandle *authHandle, const uint8_t *inData,
        uint32_t inLen, uint8_t *outData, uint32_t *outLen) = 0;

    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len) = 0;

    virtual int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len) = 0;

    virtual uint32_t ApplyLaneReqId(LaneType type) = 0;
    virtual int32_t LnnRequestLane(uint32_t laneReqId,
        const LaneRequestOption *request, const ILaneListener *listener) = 0;
    virtual int32_t LnnFreeLane(uint32_t laneReqId) = 0;
    virtual int32_t LnnGetNetworkIdByUdidHash(
        const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len, bool needOnline) = 0;
};

class TransAuthInterfaceMock : public TransAuthInterface {
public:
    TransAuthInterfaceMock();
    ~TransAuthInterfaceMock() override;

    MOCK_METHOD0(AuthInit, int32_t ());
    MOCK_METHOD0(AuthDeinit, void ());

    MOCK_METHOD1(RegAuthVerifyListener, int32_t (const AuthVerifyListener *));
    MOCK_METHOD0(UnregAuthVerifyListener, void ());
    MOCK_METHOD2(RegAuthTransListener, int32_t (int32_t, const AuthTransListener *));
    MOCK_METHOD1(UnregAuthTransListener, void (int32_t));
    MOCK_METHOD1(RegGroupChangeListener, int32_t (const GroupChangeListener *));
    MOCK_METHOD0(UnregGroupChangeListener, void ());

    MOCK_METHOD0(AuthGenRequestId, uint32_t ());
    MOCK_METHOD1(AuthFlushDevice, int32_t (const char *));
    MOCK_METHOD1(AuthHandleLeaveLNN, void (AuthHandle));
    MOCK_METHOD3(AuthStartListening, int32_t (AuthLinkType, const char *, int32_t));
    MOCK_METHOD1(AuthStopListening, void (AuthLinkType));

    MOCK_METHOD4(AuthOpenConn, int32_t (const AuthConnInfo *, uint32_t, const AuthConnCallback *, bool));
    MOCK_METHOD1(AuthCloseConn, void (AuthHandle));
    MOCK_METHOD2(AuthPostTransData, int32_t (AuthHandle, const AuthTransData *));
    MOCK_METHOD3(AuthGetPreferConnInfo, int32_t (const char *, AuthConnInfo *, bool));
    MOCK_METHOD3(AuthGetP2pConnInfo, int32_t (const char *, AuthConnInfo *, bool));
    MOCK_METHOD3(AuthGetHmlConnInfo, int32_t (const char *, AuthConnInfo *, bool));

    MOCK_METHOD4(AuthGetLatestIdByUuid, void (const char *, AuthLinkType, bool, AuthHandle *));
    MOCK_METHOD3(AuthGetIdByConnInfo, int64_t (const AuthConnInfo *, bool, bool));
    MOCK_METHOD4(AuthGetIdByP2pMac, int64_t (const char *, AuthLinkType, bool, bool));

    MOCK_METHOD2(AuthGetEncryptSize, uint32_t (int64_t authId, uint32_t inLen));
    MOCK_METHOD1(AuthGetDecryptSize, uint32_t (uint32_t));

    MOCK_METHOD2(AuthSetP2pMac, int32_t (int64_t, const char *));
    MOCK_METHOD2(AuthGetConnInfo, int32_t (AuthHandle, AuthConnInfo *));
    MOCK_METHOD2(AuthGetServerSide, int32_t (int64_t, bool *));
    MOCK_METHOD3(AuthGetDeviceUuid, int32_t (int64_t, char *, uint16_t));
    MOCK_METHOD2(AuthGetVersion, int32_t (int64_t, SoftBusVersion *));
    MOCK_METHOD2(AuthGetMetaType,     int32_t (int64_t, bool *));

    MOCK_METHOD5(AuthMetaStartVerify, int32_t (uint32_t, const AuthKeyInfo *, uint32_t, int32_t,
        const AuthVerifyCallback *));
    MOCK_METHOD1(AuthMetaReleaseVerify, void (int64_t));
    MOCK_METHOD5(AuthEncrypt, int32_t (AuthHandle *, const uint8_t *, uint32_t, uint8_t *, uint32_t *));
    MOCK_METHOD5(AuthDecrypt, int32_t (AuthHandle *, const uint8_t *, uint32_t, uint8_t *, uint32_t *));

    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char *, uint32_t));
    MOCK_METHOD3(LnnGetNetworkIdByUuid, int32_t (const char *, char *, uint32_t));

    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char *, InfoKey, char *, uint32_t));
    MOCK_METHOD3(LnnGetNetworkIdByBtMac, int32_t (const char *, char *, uint32_t));

    MOCK_METHOD1(ApplyLaneReqId, uint32_t (LaneType));
    MOCK_METHOD3(LnnRequestLane, int32_t (uint32_t, const LaneRequestOption *, const ILaneListener *));
    MOCK_METHOD1(LnnFreeLane, int32_t (uint32_t laneReqId));
    MOCK_METHOD5(LnnGetNetworkIdByUdidHash, int32_t (const uint8_t *, uint32_t, char *, uint32_t, bool));
};
} // namespace OHOS
#endif // TRANS_AUTH_MOCK_H
