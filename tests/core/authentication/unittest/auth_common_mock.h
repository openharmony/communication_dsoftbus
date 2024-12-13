/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef AUTH_COMMON_MOCK_H
#define AUTH_COMMON_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_common.h"
#include "device_auth.h"
#include "lnn_async_callback_utils.h"
#include "lnn_common_utils.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_interface.h"
#include "lnn_net_builder.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_node_info.h"
#include "softbus_adapter_bt_common.h"

namespace OHOS {
class AuthCommonInterface {
public:
    AuthCommonInterface() {};
    virtual ~AuthCommonInterface() {};

    virtual int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
        void *para, uint64_t delayMillis);
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t SoftBusGetBtState(void) = 0;
    virtual int32_t SoftBusGetBrState(void) = 0;
    virtual void LnnHbOnTrustedRelationReduced(void) = 0;
    virtual int32_t LnnInsertSpecificTrustedDevInfo(const char *udid) = 0;
    virtual int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len) = 0;
    virtual int32_t LnnGetStaFrequency(const NodeInfo *info) = 0;
    virtual int32_t LnnEncryptAesGcm(AesGcmInputParam *in, int32_t keyIndex, uint8_t **out, uint32_t *outLen) = 0;
    virtual int32_t LnnDecryptAesGcm(AesGcmInputParam *in, uint8_t **out, uint32_t *outLen) = 0;
    virtual int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num) = 0;
    virtual int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual int32_t LnnNotifyEmptySessionKey(int64_t authId) = 0;
    virtual int32_t LnnNotifyLeaveLnnByAuthHandle(AuthHandle *authHandle);
    virtual int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType);
    virtual int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info) = 0;
    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count) = 0;
    virtual void DeleteNodeFromPcRestrictMap(const char *udidHash) = 0;
    virtual int32_t AuthFailNotifyProofInfo(int32_t errCode, const char *errorReturn, uint32_t errorReturnLen) = 0;
    virtual void LnnDeleteLinkFinderInfo(const char *peerUdid) = 0;
};
class AuthCommonInterfaceMock : public AuthCommonInterface {
public:
    AuthCommonInterfaceMock();
    ~AuthCommonInterfaceMock() override;
    MOCK_METHOD3(LnnGetRemoteNumU64Info, int32_t(const char *, InfoKey, uint64_t *));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t (SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t (InfoKey, uint64_t *));
    MOCK_METHOD0(SoftBusGetBtState, int32_t (void));
    MOCK_METHOD0(SoftBusGetBrState, int32_t (void));
    MOCK_METHOD0(LnnHbOnTrustedRelationReduced, void ());
    MOCK_METHOD1(LnnInsertSpecificTrustedDevInfo, int32_t (const char *));
    MOCK_METHOD3(LnnGetNetworkIdByUuid, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD1(LnnGetStaFrequency, int32_t (const NodeInfo *));
    MOCK_METHOD4(LnnEncryptAesGcm, int32_t (AesGcmInputParam *, int32_t, uint8_t **, uint32_t *));
    MOCK_METHOD3(LnnDecryptAesGcm, int32_t (AesGcmInputParam *, uint8_t **, uint32_t *));
    MOCK_METHOD2(LnnGetTrustedDevInfoFromDb, int32_t (char **, uint32_t *));
    MOCK_METHOD1(LnnGetAllOnlineNodeNum, int32_t (int32_t *));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t (InfoKey, const char *));
    MOCK_METHOD1(LnnNotifyEmptySessionKey, int32_t (int64_t));
    MOCK_METHOD1(LnnNotifyLeaveLnnByAuthHandle, int32_t (AuthHandle *));
    MOCK_METHOD2(LnnRequestLeaveSpecific, int32_t (const char *, ConnectionAddrType));
    MOCK_METHOD1(SoftBusGetBtMacAddr, int32_t (SoftBusBtAddr *));
    MOCK_METHOD2(GetNodeFromPcRestrictMap, int32_t (const char *, uint32_t *));
    MOCK_METHOD1(DeleteNodeFromPcRestrictMap, void (const char *));
    MOCK_METHOD3(AuthFailNotifyProofInfo, int32_t (int32_t, const char *, uint32_t));
    MOCK_METHOD1(LnnDeleteLinkFinderInfo, void (const char *));
};
} // namespace OHOS
#endif // AUTH_COMMON_MOCK_H