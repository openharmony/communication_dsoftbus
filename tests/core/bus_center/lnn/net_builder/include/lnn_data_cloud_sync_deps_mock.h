/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef LNN_DATA_CLOUD_SYNC_DEPS_MOCK_H
#define LNN_DATA_CLOUD_SYNC_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "lnn_device_info_recovery.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "softbus_utils.h"
#include "lnn_async_callback_utils.h"

namespace OHOS {
class LnnDataCloudSyncInterface {
public:
    LnnDataCloudSyncInterface() {};
    virtual ~LnnDataCloudSyncInterface() {};

    virtual int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo);
    virtual int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo);
    virtual void LnnDeleteDeviceInfo(const char *udid);
    virtual int32_t LnnGetLocalCacheNodeInfo(NodeInfo *info);
    virtual int32_t LnnPackCloudSyncDeviceInfo(cJSON *json, const NodeInfo *cloudSyncInfo);
    virtual int32_t LnnUnPackCloudSyncDeviceInfo(cJSON *json, NodeInfo *cloudSyncInfo);
    virtual int32_t LnnUpdateNetworkId(const NodeInfo *newInfo) = 0;
    virtual int32_t LnnGetLocalBroadcastCipherInfo(CloudSyncInfo *info);
    virtual int32_t LnnSetRemoteBroadcastCipherInfo(const char *value, const char *udid);
    virtual int32_t LnnGenerateHexStringHash(const unsigned char *str, char *hashStr, uint32_t len);
    virtual int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen,
        const char *inBuf, uint32_t inLen);
    virtual int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
        void *para, uint64_t delayMillis);
};

class LnnDataCloudSyncInterfaceMock : public LnnDataCloudSyncInterface {
public:
    LnnDataCloudSyncInterfaceMock();
    ~LnnDataCloudSyncInterfaceMock() override;

    MOCK_METHOD1(LnnSaveRemoteDeviceInfo, int32_t (const NodeInfo *));
    MOCK_METHOD2(LnnRetrieveDeviceInfo, int32_t (const char *, NodeInfo *));
    MOCK_METHOD1(LnnDeleteDeviceInfo, void (const char *));
    MOCK_METHOD1(LnnGetLocalCacheNodeInfo, int32_t (NodeInfo *));
    MOCK_METHOD2(LnnPackCloudSyncDeviceInfo, int32_t (cJSON *, const NodeInfo *));
    MOCK_METHOD2(LnnUnPackCloudSyncDeviceInfo, int32_t (cJSON *, NodeInfo *));
    MOCK_METHOD1(LnnUpdateNetworkId, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnGetLocalBroadcastCipherInfo, int32_t (CloudSyncInfo *));
    MOCK_METHOD2(LnnSetRemoteBroadcastCipherInfo, int32_t (const char *, const char *));
    MOCK_METHOD3(LnnGenerateHexStringHash, int32_t (const unsigned char *, char *, uint32_t));
    MOCK_METHOD4(ConvertHexStringToBytes, int32_t (unsigned char *, uint32_t, const char *, uint32_t));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t (SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
};
} // namespace OHOS
#endif // LNN_AUTH_MOCK_H