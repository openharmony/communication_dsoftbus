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

#include "brproxy_fuzzer.h"

#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "br_proxy.c"

namespace OHOS {
static void FillBrProxyChannelInfo(FuzzedDataProvider &provider, BrProxyChannelInfo *channelInfo)
{
    std::string peerBRMacAddr = provider.ConsumeRandomLengthString(BR_MAC_LEN);
    std::string peerBRUuid = provider.ConsumeRandomLengthString(UUID_LEN);
    if (strcpy_s(channelInfo->peerBRMacAddr, BR_MAC_LEN, peerBRMacAddr.c_str()) != 0) {
        return;
    }
    if (strcpy_s(channelInfo->peerBRUuid, UUID_LEN, peerBRUuid.c_str()) != 0) {
        return;
    }
    channelInfo->recvPri = provider.ConsumeIntegral<int32_t>();
    channelInfo->recvPriSet = provider.ConsumeBool();
}

static int32_t onChannelOpened(int32_t sessionId, int32_t channelId, int32_t result)
{
    return SOFTBUS_OK;
}

static void onDataReceived(int32_t channelId, const char *data, uint32_t dataLen) { }

static void onChannelStatusChanged(int32_t channelId, int32_t state) { }

static BrProxyChannelInfo g_channelInfo = {
    .peerBRMacAddr = "F0:FA:C7:13:56:BC",
    .peerBRUuid = "0000FEEA-0000-1000-8000-00805F9B34FB",
    .recvPri = 1,
    .recvPriSet = true,
};

static IBrProxyListener g_listener = {
    .onChannelOpened = onChannelOpened,
    .onDataReceived = onDataReceived,
    .onChannelStatusChanged = onChannelStatusChanged,
};

void OpenBrProxyTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    BrProxyChannelInfo channelInfo;
    IBrProxyListener listener = {
        .onChannelOpened = onChannelOpened,
        .onDataReceived = onDataReceived,
        .onChannelStatusChanged = onChannelStatusChanged,
    };
    (void)memset_s(&channelInfo, sizeof(BrProxyChannelInfo), 0, sizeof(BrProxyChannelInfo));
    FillBrProxyChannelInfo(provider, &channelInfo);

    (void)OpenBrProxy(channelId, &channelInfo, &listener);
    (void)OpenBrProxy(channelId, &g_channelInfo, &g_listener);
}

void CloseBrProxyTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)CloseBrProxy(channelId);
}

void SendBrProxyDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    uint32_t dataLen = provider.ConsumeIntegralInRange<uint32_t>(0, BR_PROXY_SEND_MAX_LEN);
    std::string data = provider.ConsumeBytesAsString(BR_PROXY_SEND_MAX_LEN);
    char myData[BR_PROXY_SEND_MAX_LEN + 1];
    if (strcpy_s(myData, sizeof(myData), data.c_str()) != 0) {
        return;
    }

    (void)SendBrProxyData(channelId, myData, dataLen);
}

void SetListenerStateTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    bool isEnable = provider.ConsumeBool();
    ListenerType type =
        static_cast<ListenerType>(provider.ConsumeIntegralInRange<uint32_t>(DATA_RECEIVE, LISTENER_TYPE_MAX));

    (void)SetListenerState(channelId, type, isEnable);
}

void IsProxyChannelEnabledTest(FuzzedDataProvider &provider)
{
    int32_t uid = provider.ConsumeIntegral<int32_t>();

    (void)IsProxyChannelEnabled(uid);
}

void TransClientInitTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)TransClientInit();
}

void ClientAddChannelToListTest(FuzzedDataProvider &provider)
{
    int32_t sessionId = provider.ConsumeIntegral<int32_t>();
    BrProxyChannelInfo channelInfo;
    IBrProxyListener listener = {
        .onChannelOpened = onChannelOpened,
        .onDataReceived = onDataReceived,
        .onChannelStatusChanged = onChannelStatusChanged,
    };
    (void)memset_s(&channelInfo, sizeof(BrProxyChannelInfo), 0, sizeof(BrProxyChannelInfo));
    FillBrProxyChannelInfo(provider, &channelInfo);

    (void)ClientAddChannelToList(sessionId, nullptr, nullptr);
    (void)ClientAddChannelToList(sessionId, &channelInfo, &listener);
}

void ClientDeleteChannelFromListTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerBrMac = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    std::string providerUuid = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char brMac[UINT8_MAX] = { 0 };
    char uuid[UINT8_MAX] = { 0 };
    if (strcpy_s(brMac, UINT8_MAX, providerBrMac.c_str()) != EOK ||
        strcpy_s(uuid, UINT8_MAX, providerUuid.c_str()) != EOK) {
        return;
    }

    (void)ClientDeleteChannelFromList(channelId, nullptr, uuid);
    (void)ClientDeleteChannelFromList(channelId, brMac, uuid);
}

void ClientUpdateListtTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerMac = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    std::string providerUuid = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char mac[UINT8_MAX] = { 0 };
    char uuid[UINT8_MAX] = { 0 };
    if (strcpy_s(mac, UINT8_MAX, providerMac.c_str()) != EOK ||
        strcpy_s(uuid, UINT8_MAX, providerUuid.c_str()) != EOK) {
        return;
    }

    (void)ClientUpdateList(mac, uuid, channelId);
}

void ClientQueryListTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerPeerBRMacAddr = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    std::string providerUuid = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char peerBRMacAddr[UINT8_MAX] = { 0 };
    char uuid[UINT8_MAX] = { 0 };
    if (strcpy_s(peerBRMacAddr, UINT8_MAX, providerPeerBRMacAddr.c_str()) != EOK ||
        strcpy_s(uuid, UINT8_MAX, providerUuid.c_str()) != EOK) {
        return;
    }
    ClientBrProxyChannelInfo info;
    (void)memset_s(&info, sizeof(ClientBrProxyChannelInfo), 0, sizeof(ClientBrProxyChannelInfo));

    (void)ClientQueryList(channelId, peerBRMacAddr, uuid, &info);
}

void ClientRecordListenerStateTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    ListenerType type =
        static_cast<ListenerType>(provider.ConsumeIntegralInRange<uint32_t>(DATA_RECEIVE, LISTENER_TYPE_MAX));
    bool isEnable = provider.ConsumeBool();

    (void)ClientRecordListenerState(channelId, type, isEnable);
}

void ClientTransBrProxyDataReceivedTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    uint32_t len = provider.ConsumeIntegral<uint32_t>();

    (void)ClientTransBrProxyDataReceived(channelId, nullptr, len);
}

void SoftbusErrConvertChannelStateTest(FuzzedDataProvider &provider)
{
    int32_t err = provider.ConsumeIntegral<int32_t>();

    (void)SoftbusErrConvertChannelState(err);
}

void ClientTransBrProxyChannelChangeTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t errCode = provider.ConsumeIntegral<int32_t>();

    (void)ClientTransBrProxyChannelChange(channelId, errCode);
}

void ClientTransOnBrProxyOpenedTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t result = provider.ConsumeIntegral<int32_t>();
    std::string providerBrMac = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    std::string providerUuid = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char brMac[UINT8_MAX] = { 0 };
    char uuid[UINT8_MAX] = { 0 };
    if (strcpy_s(brMac, UINT8_MAX, providerBrMac.c_str()) != EOK ||
        strcpy_s(uuid, UINT8_MAX, providerUuid.c_str()) != EOK) {
        return;
    }

    (void)ClientTransOnBrProxyOpened(channelId, nullptr, nullptr, result);
    (void)ClientTransOnBrProxyOpened(channelId, brMac, uuid, result);
}

void RegisterAccessHookTest(FuzzedDataProvider &provider)
{
    (void)provider;
    PermissonHookCb cb;
    (void)memset_s(&cb, sizeof(PermissonHookCb), 0, sizeof(PermissonHookCb));

    (void)RegisterAccessHook(nullptr);
    (void)RegisterAccessHook(&cb);
}

void ClientTransBrProxyQueryPermissionTest(FuzzedDataProvider &provider)
{
    std::string providerBundleName = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char bundleName[UINT8_MAX] = { 0 };
    if (strcpy_s(bundleName, UINT8_MAX, providerBundleName.c_str()) != EOK) {
        return;
    }
    bool isEmpowered;

    (void)ClientTransBrProxyQueryPermission(nullptr, nullptr);
    (void)ClientTransBrProxyQueryPermission(bundleName, &isEmpowered);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::OpenBrProxyTest(provider);
    OHOS::CloseBrProxyTest(provider);
    OHOS::SendBrProxyDataTest(provider);
    OHOS::SetListenerStateTest(provider);
    OHOS::IsProxyChannelEnabledTest(provider);
    OHOS::TransClientInitTest(provider);
    OHOS::ClientAddChannelToListTest(provider);
    OHOS::ClientUpdateListtTest(provider);
    OHOS::ClientQueryListTest(provider);
    OHOS::ClientRecordListenerStateTest(provider);
    OHOS::ClientTransBrProxyDataReceivedTest(provider);
    OHOS::SoftbusErrConvertChannelStateTest(provider);
    OHOS::ClientTransBrProxyChannelChangeTest(provider);
    OHOS::ClientTransOnBrProxyOpenedTest(provider);
    OHOS::RegisterAccessHookTest(provider);
    OHOS::ClientTransBrProxyQueryPermissionTest(provider);
    OHOS::ClientDeleteChannelFromListTest(provider);

    return 0;
}