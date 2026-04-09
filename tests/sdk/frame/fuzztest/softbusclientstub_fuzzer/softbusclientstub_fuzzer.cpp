/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "client_trans_channel_manager.h"
#include "fuzz_data_generator.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_client_stub.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t UUID_STRING_LEN = 38;
constexpr size_t HAP_NAME_MAX_LEN = 256;

class TestEnv {
public:
    TestEnv()
    {
        isInited_ = false;
        ClientTransChannelInit();
        isInited_ = true;
    }

    ~TestEnv()
    {
        isInited_ = false;
        ClientTransChannelDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

enum SoftBusFuncId {
    CLIENT_ON_CHANNEL_OPENED = 256,
    CLIENT_ON_CHANNEL_OPENFAILED,
    CLIENT_ON_CHANNEL_LINKDOWN,
    CLIENT_ON_CHANNEL_CLOSED,
    CLIENT_ON_CHANNEL_MSGRECEIVED,
    CLIENT_ON_CHANNEL_QOSEVENT,

    CLIENT_DISCOVERY_DEVICE_FOUND,

    CLIENT_ON_JOIN_RESULT,
    CLIENT_ON_JOIN_METANODE_RESULT,
    CLIENT_ON_LEAVE_RESULT,
    CLIENT_ON_LEAVE_METANODE_RESULT,
    CLIENT_ON_NODE_DEVICE_TRUST_CHANGED,
    CLIENT_ON_HICHAIN_PROOF_EXCEPTION,
    CLIENT_ON_NODE_ONLINE_STATE_CHANGED,
    CLIENT_ON_NODE_BASIC_INFO_CHANGED,
    CLIENT_ON_LOCAL_NETWORK_ID_CHANGED,
    CLIENT_ON_TIME_SYNC_RESULT,
    CLIENT_ON_PUBLISH_LNN_RESULT,
    CLIENT_ON_REFRESH_LNN_RESULT,
    CLIENT_ON_REFRESH_DEVICE_FOUND,
    CLIENT_ON_PERMISSION_CHANGE,
    CLIENT_SET_CHANNEL_INFO,
    CLIENT_ON_DATA_LEVEL_CHANGED,
    CLIENT_ON_TRANS_LIMIT_CHANGE,
    CLIENT_ON_CHANNEL_BIND,
    CLIENT_CHECK_COLLAB_RELATION,
};

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

bool OnChannelOpenFailedInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_OPENFAILED, datas, reply, option);

    return true;
}

bool OnChannelLinkDownInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    std::string providerNetworkId = provider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN - 1);
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN - 1, providerNetworkId.c_str()) != EOK) {
        return false;
    }

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;

    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteCString(networkId);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_LINKDOWN, datas, reply, option);

    return true;
}

bool OnChannelClosedInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_CLOSED, datas, reply, option);

    return true;
}

bool OnChannelMsgReceivedInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    if (len < 1) {
        return false;
    }
    std::string dataInfo = provider.ConsumeBytesAsString(len - 1);

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteUint32(dataInfo.size());
    datas.WriteRawData(dataInfo.c_str(), dataInfo.size());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_MSGRECEIVED, datas, reply, option);

    return true;
}

bool OnChannelQosEventInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    WifiChannelQuality wifiChannelInfo = { 0 };
    wifiChannelInfo.channel = provider.ConsumeIntegral<int32_t>();
    wifiChannelInfo.score = provider.ConsumeIntegral<int32_t>();
    QosTv qosTv = {
        .type = WIFI_CHANNEL_QUALITY,
        .info.wifiChannelInfo = wifiChannelInfo,
    };

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(sizeof(qosTv));
    datas.WriteRawData(&qosTv, sizeof(qosTv));
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_QOSEVENT, datas, reply, option);

    return true;
}

bool OnJoinLNNResultInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    std::string providerNetworkId = provider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN - 1);
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN - 1, providerNetworkId.c_str()) != EOK) {
        return false;
    }
    uint32_t addrTypeLen = sizeof(ConnectionAddr);
    std::string addr = provider.ConsumeBytesAsString(addrTypeLen - 1);

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteUint32(addr.size());
    datas.WriteRawData(addr.c_str(), addr.size());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteCString(networkId);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_JOIN_RESULT, datas, reply, option);
    return true;
}

bool OnJoinMetaNodeResultInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    uint32_t addrTypeLen = sizeof(ConnectionAddr);
    std::string addr = provider.ConsumeBytesAsString(addrTypeLen - 1);
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteUint32(addr.size());
    datas.WriteRawData(addr.c_str(), addr.size());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    MessageParcel reply;
    MessageOption option;
    softBusClientStub->OnRemoteRequest(CLIENT_ON_JOIN_METANODE_RESULT, datas, reply, option);
    return true;
}

bool OnLeaveLNNResultInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    std::string providerNetworkId = provider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN - 1);
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN - 1, providerNetworkId.c_str()) != EOK) {
        return false;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteCString(networkId);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    MessageParcel reply;
    MessageOption option;
    softBusClientStub->OnRemoteRequest(CLIENT_ON_LEAVE_RESULT, datas, reply, option);
    return true;
}

bool OnLeaveMetaNodeResultInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    MessageParcel reply;
    MessageOption option;
    softBusClientStub->OnRemoteRequest(CLIENT_ON_LEAVE_METANODE_RESULT, datas, reply, option);
    return true;
}

bool OnNodeDeviceTrustedChangeInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    MessageParcel reply;
    MessageOption option;
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return false;
    }
    datas.WriteCString(pkgName);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    uint32_t msgLen = provider.ConsumeIntegral<uint32_t>();
    if (msgLen < 1) {
        return false;
    }
    std::string msg = provider.ConsumeBytesAsString(msgLen - 1);
    datas.WriteCString(msg.c_str());
    datas.WriteUint32(msgLen);

    softBusClientStub->OnRemoteRequest(CLIENT_ON_NODE_DEVICE_TRUST_CHANGED, datas, reply, option);
    return true;
}

bool OnHichainProofExceptionInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    MessageParcel reply;
    MessageOption option;
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return false;
    }
    datas.WriteCString(pkgName);
    uint32_t proofLen = provider.ConsumeIntegral<uint32_t>();
    if (proofLen < 1) {
        return false;
    }
    std::string proofInfo = provider.ConsumeBytesAsString(proofLen - 1);
    datas.WriteUint32(proofInfo.size());
    datas.WriteRawData(proofInfo.c_str(), proofInfo.size());
    datas.WriteUint16(provider.ConsumeIntegral<uint16_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());

    softBusClientStub->OnRemoteRequest(CLIENT_ON_HICHAIN_PROOF_EXCEPTION, datas, reply, option);
    return true;
}

bool OnNodeOnlineStateChangedInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return false;
    }
    datas.WriteCString(pkgName);
    datas.WriteBool(provider.ConsumeBool());
    uint32_t infoTypeLen = provider.ConsumeIntegral<uint32_t>();
    if (infoTypeLen < 1) {
        return false;
    }
    std::string info = provider.ConsumeBytesAsString(infoTypeLen - 1);
    datas.WriteUint32(info.size());
    datas.WriteRawData(info.c_str(), info.size());

    MessageParcel reply;
    MessageOption option;
    softBusClientStub->OnRemoteRequest(CLIENT_ON_NODE_ONLINE_STATE_CHANGED, datas, reply, option);
    return true;
}

bool OnNodeBasicInfoChangedInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    MessageParcel reply;
    MessageOption option;
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return false;
    }
    datas.WriteCString(pkgName);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    uint32_t infoTypeLen = provider.ConsumeIntegral<uint32_t>();
    if (infoTypeLen < 1) {
        return false;
    }
    std::string info = provider.ConsumeBytesAsString(infoTypeLen - 1);
    datas.WriteUint32(info.size());
    datas.WriteRawData(info.c_str(), info.size());

    softBusClientStub->OnRemoteRequest(CLIENT_ON_NODE_BASIC_INFO_CHANGED, datas, reply, option);
    return true;
}

bool OnTimeSyncResultInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    MessageParcel reply;
    MessageOption option;
    uint32_t infoTypeLen = provider.ConsumeIntegral<uint32_t>();
    if (infoTypeLen < 1) {
        return false;
    }
    std::string info = provider.ConsumeBytesAsString(infoTypeLen - 1);
    datas.WriteUint32(info.size());
    datas.WriteRawData(info.c_str(), info.size());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());

    softBusClientStub->OnRemoteRequest(CLIENT_ON_TIME_SYNC_RESULT, datas, reply, option);
    return true;
}

bool OnPublishLNNResultInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    MessageParcel reply;
    MessageOption option;
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());

    softBusClientStub->OnRemoteRequest(CLIENT_ON_PUBLISH_LNN_RESULT, datas, reply, option);
    return true;
}

bool OnRefreshLNNResultInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    MessageParcel reply;
    MessageOption option;
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());

    softBusClientStub->OnRemoteRequest(CLIENT_ON_REFRESH_LNN_RESULT, datas, reply, option);
    return true;
}

bool OnRefreshDeviceFoundInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    MessageParcel reply;
    MessageOption option;
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());

    softBusClientStub->OnRemoteRequest(CLIENT_ON_REFRESH_DEVICE_FOUND, datas, reply, option);
    return true;
}

bool OnClientPermissionChangeInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return false;
    }
    datas.WriteCString(pkgName);

    softBusClientStub->OnRemoteRequest(CLIENT_ON_PERMISSION_CHANGE, datas, reply, option);

    return true;
}

bool OnClientTransLimitChangeInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    MessageParcel reply;
    MessageOption option;
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteUint8(provider.ConsumeIntegral<int8_t>());

    softBusClientStub->OnRemoteRequest(CLIENT_ON_TRANS_LIMIT_CHANGE, datas, reply, option);
    return true;
}

bool SetChannelInfoInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    std::string providerSessionName = provider.ConsumeBytesAsString(SESSION_NAME_SIZE_MAX - 1);
    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX - 1, providerSessionName.c_str()) != EOK) {
        return false;
    }
    datas.WriteCString(sessionName);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    softBusClientStub->OnRemoteRequest(CLIENT_SET_CHANNEL_INFO, datas, reply, option);

    return true;
}

bool OnChannelBindInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    datas.WriteInt32(provider.ConsumeIntegral<int32_t>());
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_BIND, datas, reply, option);

    return true;
}

bool OnChannelOnQosInnerTest(FuzzedDataProvider &provider)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegral<int32_t>();
    int32_t event = provider.ConsumeIntegral<int32_t>();
    uint32_t count = provider.ConsumeIntegral<uint32_t>();
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteInt32(event);
    datas.WriteUint32(count);
    softBusClientStub->OnRemoteRequest(CLIENT_CHANNEL_ON_QOS, datas, reply, option);
    return true;
}

static bool FillCollabInfo(CollabInfo *info, FuzzedDataProvider &provider)
{
    if (info == NULL) {
        return false;
    }
    std::string providerAccountId = provider.ConsumeBytesAsString(ACCOUNT_UID_LEN_MAX - 1);
    if (strcpy_s(info->accountId, ACCOUNT_UID_LEN_MAX - 1, providerAccountId.c_str()) != EOK) {
        return false;
    }
    info->tokenId = provider.ConsumeIntegral<uint64_t>();
    info->userId = provider.ConsumeIntegral<int32_t>();
    info->pid = provider.ConsumeIntegral<int32_t>();
    std::string providerDeviceId = provider.ConsumeBytesAsString(DEVICE_ID_LEN_MAX - 1);
    if (strcpy_s(info->deviceId, DEVICE_ID_LEN_MAX - 1, providerDeviceId.c_str()) != EOK) {
        return false;
    }
    return true;
}

static void WriteCollabInfo(MessageParcel &datas, CollabInfo &info)
{
    datas.WriteCString(info.accountId);
    datas.WriteUint64(info.tokenId);
    datas.WriteInt32(info.userId);
    datas.WriteInt32(info.pid);
    datas.WriteCString(info.deviceId);
}

bool OnCheckCollabRelationInnerTest(FuzzedDataProvider &provider)
{
    bool isSinkSide = provider.ConsumeBool();
    int32_t channelId = provider.ConsumeIntegral<uint32_t>();
    int32_t channelType = provider.ConsumeIntegral<uint32_t>();
    CollabInfo sourceInfo;
    (void)memset_s(&sourceInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    if (!FillCollabInfo(&sourceInfo, provider)) {
        return false;
    }

    CollabInfo sinkInfo;
    (void)memset_s(&sinkInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    if (!FillCollabInfo(&sinkInfo, provider)) {
        return false;
    }

    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteBool(isSinkSide);
    WriteCollabInfo(datas, sourceInfo);
    WriteCollabInfo(datas, sinkInfo);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    softBusClientStub->OnRemoteRequest(CLIENT_CHECK_COLLAB_RELATION, datas, reply, option);
    return true;
}

bool OnBrProxyOpenedInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t reason = provider.ConsumeIntegral<int32_t>();
    char brMac[BT_MAC_LEN] = { 0 };
    char uuid[UUID_STRING_LEN] = { 0 };
    std::string providerBrMac = provider.ConsumeBytesAsString(BT_MAC_LEN - 1);
    if (strcpy_s(brMac, BT_MAC_LEN - 1, providerBrMac.c_str()) != EOK) {
        return false;
    }
    std::string providerUuid = provider.ConsumeBytesAsString(UUID_STRING_LEN - 1);
    if (strcpy_s(uuid, UUID_STRING_LEN - 1, providerUuid.c_str()) != EOK) {
        return false;
    }
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(reason);
    datas.WriteCString(brMac);
    datas.WriteCString(uuid);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_BR_PROXY_OPENED, datas, reply, option);
    return true;
}

bool OnBrProxyDataRecvInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    uint32_t len = provider.ConsumeIntegralInRange<int32_t>(0, FOO_MAX_LEN);
    uint8_t dataInfo[FOO_MAX_LEN] = { 0 };
    if (len < 1) {
        return false;
    }
    std::string providerDataInfo = provider.ConsumeBytesAsString(len - 1);
    if (strcpy_s((char *)dataInfo, len - 1, providerDataInfo.c_str()) != EOK) {
        return false;
    }
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteUint32(len);
    datas.WriteRawData(dataInfo, len);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_BR_PROXY_DATA_RECV, datas, reply, option);
    return true;
}

bool OnBrProxyStateChangedInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(errCode);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_BR_PROXY_STATE_CHANGED, datas, reply, option);
    return true;
}

bool OnBrProxyQueryPermissionInnerTest(FuzzedDataProvider &provider)
{
    char bundleName[HAP_NAME_MAX_LEN] = { 0 };
    std::string providerBundleName = provider.ConsumeBytesAsString(HAP_NAME_MAX_LEN - 1);
    if (strcpy_s(bundleName, HAP_NAME_MAX_LEN - 1, providerBundleName.c_str()) != EOK) {
        return false;
    }
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteCString(bundleName);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_BR_PROXY_QUERY_PERMISSION, datas, reply, option);
    return true;
}

bool OnConnectionStateChangeInnerTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    int32_t state = provider.ConsumeIntegral<int32_t>();
    int32_t reason = provider.ConsumeIntegral<int32_t>();

    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteUint32(handle);
    datas.WriteInt32(state);
    datas.WriteInt32(reason);
    softBusClientStub->OnRemoteRequest(CLIENT_GENERAL_CONNECTION_STATE_CHANGE, datas, reply, option);
    return true;
}

bool OnDataReceivedInnerTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    uint32_t len = provider.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    uint8_t dataPtr[U32_AT_SIZE] = { 0 };
    if (len < 1) {
        return false;
    }
    std::string providerDataInfo = provider.ConsumeBytesAsString(len - 1);
    if (strcpy_s((char *)dataPtr, len - 1, providerDataInfo.c_str()) != EOK) {
        return false;
    }

    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteUint32(handle);
    datas.WriteUint32(len);
    datas.WriteRawData(dataPtr, len);
    softBusClientStub->OnRemoteRequest(CLIENT_GENERAL_DATA_RECEIVED, datas, reply, option);
    return true;
}

bool OnAcceptConnectInnerTest(FuzzedDataProvider &provider)
{
    char name[HAP_NAME_MAX_LEN] = { 0 };
    std::string providerName = provider.ConsumeBytesAsString(HAP_NAME_MAX_LEN - 1);
    if (strcpy_s(name, HAP_NAME_MAX_LEN - 1, providerName.c_str()) != EOK) {
        return false;
    }
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();

    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteCString(name);
    datas.WriteUint32(handle);
    softBusClientStub->OnRemoteRequest(CLIENT_GENERAL_ACCEPT_CONNECT, datas, reply, option);
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
    OHOS::OnChannelOpenFailedInnerTest(provider);
    OHOS::OnChannelLinkDownInnerTest(provider);
    OHOS::OnChannelClosedInnerTest(provider);
    OHOS::OnChannelMsgReceivedInnerTest(provider);
    OHOS::OnChannelQosEventInnerTest(provider);
    OHOS::OnJoinLNNResultInnerTest(provider);
    OHOS::OnJoinMetaNodeResultInnerTest(provider);
    OHOS::OnLeaveLNNResultInnerTest(provider);
    OHOS::OnLeaveMetaNodeResultInnerTest(provider);
    OHOS::OnHichainProofExceptionInnerTest(provider);
    OHOS::OnNodeOnlineStateChangedInnerTest(provider);
    OHOS::OnNodeBasicInfoChangedInnerTest(provider);
    OHOS::OnTimeSyncResultInnerTest(provider);
    OHOS::OnPublishLNNResultInnerTest(provider);
    OHOS::OnRefreshLNNResultInnerTest(provider);
    OHOS::OnRefreshDeviceFoundInnerTest(provider);
    OHOS::OnClientPermissionChangeInnerTest(provider);
    OHOS::OnClientTransLimitChangeInnerTest(provider);
    OHOS::SetChannelInfoInnerTest(provider);
    OHOS::OnChannelBindInnerTest(provider);
    OHOS::OnChannelOnQosInnerTest(provider);
    OHOS::OnCheckCollabRelationInnerTest(provider);
    OHOS::OnBrProxyOpenedInnerTest(provider);
    OHOS::OnBrProxyDataRecvInnerTest(provider);
    OHOS::OnBrProxyStateChangedInnerTest(provider);
    OHOS::OnBrProxyQueryPermissionInnerTest(provider);
    OHOS::OnConnectionStateChangeInnerTest(provider);
    OHOS::OnDataReceivedInnerTest(provider);
    OHOS::OnAcceptConnectInnerTest(provider);
    return 0;
}
