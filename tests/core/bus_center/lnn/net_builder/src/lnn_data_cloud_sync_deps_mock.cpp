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

#include "lnn_data_cloud_sync_deps_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_dataCloudSyncInterface;
LnnDataCloudSyncInterfaceMock::LnnDataCloudSyncInterfaceMock()
{
    g_dataCloudSyncInterface = reinterpret_cast<void *>(this);
}

LnnDataCloudSyncInterfaceMock::~LnnDataCloudSyncInterfaceMock()
{
    g_dataCloudSyncInterface = nullptr;
}

static LnnDataCloudSyncInterface *GetDataCloudSyncInterface()
{
    return reinterpret_cast<LnnDataCloudSyncInterface *>(g_dataCloudSyncInterface);
}

extern "C" {
int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo)
{
    return GetDataCloudSyncInterface()->LnnSaveRemoteDeviceInfo(deviceInfo);
}

int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo)
{
    return GetDataCloudSyncInterface()->LnnRetrieveDeviceInfo(udid, deviceInfo);
}

void LnnDeleteDeviceInfo(const char *udid)
{
    return GetDataCloudSyncInterface()->LnnDeleteDeviceInfo(udid);
}

int32_t LnnGetLocalCacheNodeInfo(NodeInfo *info)
{
    return GetDataCloudSyncInterface()->LnnGetLocalCacheNodeInfo(info);
}

int32_t LnnPackCloudSyncDeviceInfo(cJSON *json, const NodeInfo *cloudSyncInfo)
{
    return GetDataCloudSyncInterface()->LnnPackCloudSyncDeviceInfo(json, cloudSyncInfo);
}

int32_t LnnUnPackCloudSyncDeviceInfo(cJSON *json, NodeInfo *cloudSyncInfo)
{
    return GetDataCloudSyncInterface()->LnnUnPackCloudSyncDeviceInfo(json, cloudSyncInfo);
}

int32_t LnnUpdateNetworkId(const NodeInfo *newInfo)
{
    return GetDataCloudSyncInterface()->LnnUpdateNetworkId(newInfo);
}

int32_t LnnGetLocalBroadcastCipherInfo(CloudSyncInfo *info)
{
    return GetDataCloudSyncInterface()->LnnGetLocalBroadcastCipherInfo(info);
}

int32_t LnnSetRemoteBroadcastCipherInfo(const char *value, const char *udid)
{
    return GetDataCloudSyncInterface()->LnnSetRemoteBroadcastCipherInfo(value, udid);
}

int32_t LnnGenerateHexStringHash(const unsigned char *str, char *hashStr, uint32_t len)
{
    return GetDataCloudSyncInterface()->LnnGenerateHexStringHash(str, hashStr, len);
}

int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen, const char *inBuf, uint32_t inLen)
{
    return GetDataCloudSyncInterface()->ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
}

int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis)
{
    return GetDataCloudSyncInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}
}
} // namespace OHOS