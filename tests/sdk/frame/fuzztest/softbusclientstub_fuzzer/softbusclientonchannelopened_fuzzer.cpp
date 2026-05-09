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

#include "softbusclientstub_fuzzer.h"

#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "fuzz_data_generator.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_client_stub.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {

const std::u16string SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusClient";

static void InitOnChannelOpenedInnerMsgExxx(
    FuzzedDataProvider &provider, MessageParcel &message, bool isServer, int32_t channelType)
{
    int32_t tokenType = provider.ConsumeIntegral<int32_t>();
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    char peerExtraAccessInfo[EXTRA_ACCESS_INFO_LEN_MAX] = { 0 };
    char groupId[GROUP_ID_SIZE_MAX] = { 0 };
    std::string providerSessionKey = provider.ConsumeBytesAsString(SESSION_KEY_LENGTH - 1);
    if (strcpy_s(sessionKey, SESSION_KEY_LENGTH, providerSessionKey.c_str()) != EOK) {
        return;
    }
    std::string providerPeerExtraAccessInfo = provider.ConsumeBytesAsString(EXTRA_ACCESS_INFO_LEN_MAX - 1);
    if (strcpy_s(peerExtraAccessInfo, EXTRA_ACCESS_INFO_LEN_MAX, providerPeerExtraAccessInfo.c_str()) != EOK) {
        return;
    }
    std::string providerGroupId = provider.ConsumeBytesAsString(GROUP_ID_SIZE_MAX - 1);
    if (strcpy_s(groupId, GROUP_ID_SIZE_MAX, providerGroupId.c_str()) != EOK) {
        return;
    }
    message.WriteInt32(tokenType);
    if (tokenType > ACCESS_TOKEN_TYPE_HAP && channelType != CHANNEL_TYPE_AUTH && isServer) {
        message.WriteInt32(provider.ConsumeIntegral<int32_t>());
        message.WriteUint32(provider.ConsumeIntegral<uint32_t>());
        message.WriteCString(peerExtraAccessInfo);
    }
    message.WriteRawData(sessionKey, SESSION_KEY_LENGTH);
    message.WriteCString(groupId);
    message.WriteBool(provider.ConsumeBool());
}

static void InitOnChannelOpenedInnerMsgExx(
    FuzzedDataProvider &provider, MessageParcel &message, bool isServer, int32_t channelType)
{
    bool isD2D = provider.ConsumeBool();
    message.WriteBool(isD2D);
    char pagingNonce[PAGING_NONCE_LEN] = { 0 };
    char pagingSessionkey[SHORT_SESSION_KEY_LENGTH] = { 0 };
    char pagingAccountId[ACCOUNT_UID_LEN_MAX] = { 0 };
    std::string providerPagingNonce = provider.ConsumeBytesAsString(PAGING_NONCE_LEN - 1);
    if (strcpy_s(pagingNonce, PAGING_NONCE_LEN - 1, providerPagingNonce.c_str()) != EOK) {
        return;
    }
    std::string providerPagingSessionkey = provider.ConsumeBytesAsString(SHORT_SESSION_KEY_LENGTH - 1);
    if (strcpy_s(pagingSessionkey, SHORT_SESSION_KEY_LENGTH - 1, providerPagingSessionkey.c_str()) != EOK) {
        return;
    }
    std::string providerPagingAccountId = provider.ConsumeBytesAsString(ACCOUNT_UID_LEN_MAX - 1);
    if (strcpy_s(pagingAccountId, ACCOUNT_UID_LEN_MAX - 1, providerPagingAccountId.c_str()) != EOK) {
        return;
    }
    if (isD2D) {
        message.WriteBool(provider.ConsumeBool());
        message.WriteInt32(provider.ConsumeIntegral<int32_t>());
        message.WriteUint32(provider.ConsumeIntegral<uint32_t>());
        message.WriteUint32(provider.ConsumeIntegral<uint32_t>());
        message.WriteRawData(pagingNonce, PAGING_NONCE_LEN);
        message.WriteRawData(pagingSessionkey, SHORT_SESSION_KEY_LENGTH);
        message.WriteUint32(0);
        if (isServer) {
            message.WriteCString(pagingAccountId);
        }
    } else {
        InitOnChannelOpenedInnerMsgExxx(provider, message, isServer, channelType);
    }
    message.WriteBool(provider.ConsumeBool());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
}

static void InitOnChannelOpenedInnerMsgEx(
    int32_t channelType, bool isServer, FuzzedDataProvider &provider, MessageParcel &message)
{
    char peerSessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    char myIp [IP_LEN] = { 0 };
    char peerIp [IP_LEN] = { 0 };
    char peerDeviceId[DEVICE_ID_SIZE_MAX] = { 0 };
    std::string providerPeerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(peerSessionName, SESSION_NAME_SIZE_MAX - 1, providerPeerSessionName.c_str()) != EOK) {
        return;
    }
    std::string providerIp = provider.ConsumeBytesAsString(IP_LEN - 1);
    if (strcpy_s(myIp, IP_LEN - 1, providerIp.c_str()) != EOK) {
        return;
    }
    std::string providerpeerIp = provider.ConsumeBytesAsString(IP_LEN - 1);
    if (strcpy_s(peerIp, IP_LEN - 1, providerpeerIp.c_str()) != EOK) {
        return;
    }
    std::string providerPeerDeviceId = provider.ConsumeBytesAsString(DEVICE_ID_SIZE_MAX - 1);
    if (strcpy_s(peerDeviceId, DEVICE_ID_SIZE_MAX - 1, providerPeerDeviceId.c_str()) != EOK) {
        return;
    }
    message.WriteCString(peerSessionName);
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    if (channelType == CHANNEL_TYPE_UDP) {
        message.WriteCString(myIp);
        message.WriteInt32(provider.ConsumeIntegral<int32_t>());
        message.WriteBool(provider.ConsumeBool());
        if (!isServer) {
            message.WriteInt32(provider.ConsumeIntegral<int32_t>());
            message.WriteCString(peerIp);
        }
    }
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteUint32(provider.ConsumeIntegral<uint32_t>());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteBool(provider.ConsumeBool());
    message.WriteCString(peerDeviceId);
    InitOnChannelOpenedInnerMsgExx(provider, message, isServer, channelType);
}

static void InitOnChannelOpenedInnerMsg(FuzzedDataProvider &provider, MessageParcel &message)
{
    bool isServer = provider.ConsumeBool();
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    char myIp [IP_LEN] = { 0 };
    char peerIp [IP_LEN] = { 0 };
    int32_t channelType = provider.ConsumeIntegralInRange<int32_t>(CHANNEL_TYPE_TCP_DIRECT, CHANNEL_TYPE_AUTH);
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerSessionName.c_str()) != EOK) {
        return;
    }
    std::string providerIp = provider.ConsumeBytesAsString(IP_LEN - 1);
    if (strcpy_s(myIp, IP_LEN - 1, providerIp.c_str()) != EOK) {
        return;
    }
    std::string providerpeerIp = provider.ConsumeBytesAsString(IP_LEN - 1);
    if (strcpy_s(peerIp, IP_LEN - 1, providerpeerIp.c_str()) != EOK) {
        return;
    }
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return;
    }
    message.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    message.WriteCString(sessionName);
    message.WriteBool(provider.ConsumeBool());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteInt32(channelType);
    message.WriteUint64(provider.ConsumeIntegral<uint64_t>());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    if (channelType == CHANNEL_TYPE_TCP_DIRECT) {
        message.WriteFileDescriptor(provider.ConsumeIntegral<int32_t>());
        message.WriteCString(myIp);
        message.WriteUint32(provider.ConsumeIntegral<uint32_t>());
        message.WriteCString(peerIp);
        message.WriteInt32(provider.ConsumeIntegral<int32_t>());
        message.WriteCString(pkgName);
    }
    message.WriteBool(isServer);
    message.WriteBool(provider.ConsumeBool());
    message.WriteBool(provider.ConsumeBool());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteInt32(provider.ConsumeIntegral<int32_t>());
    message.WriteUint32(SESSION_KEY_LENGTH);
    InitOnChannelOpenedInnerMsgEx(channelType, isServer, provider, message);
}

/*
 * Due to FileDescriptor is invalid, CHANNEL_TYPE_TCP_DIRECT will read it and crash
 * Do not add test case which channel type is CHANNEL_TYPE_TCP_DIRECT
 */
bool OnChannelOpenedInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    MessageParcel dataUdp;
    InitOnChannelOpenedInnerMsg(provider, dataUdp);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_OPENED, dataUdp, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TestEnv env;
    if (!env.IsInited()) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::OnChannelOpenedInnerTest(provider);
    return 0;
}
