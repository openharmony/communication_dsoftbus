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

#include "softbusclientstub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "client_trans_channel_manager.h"
#include "message_parcel.h"
#include "securec.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_stub.h"

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

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

    CLIENT_DISCOVERY_SUCC,
    CLIENT_DISCOVERY_FAIL,
    CLIENT_DISCOVERY_DEVICE_FOUND,
    CLIENT_PUBLISH_SUCC,
    CLIENT_PUBLISH_FAIL,

    CLIENT_ON_JOIN_RESULT,
    CLIENT_ON_JOIN_METANODE_RESULT,
    CLIENT_ON_LEAVE_RESULT,
    CLIENT_ON_LEAVE_METANODE_RESULT,
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
};

const std::u16string SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusClient";

static void InitOnChannelOpenedInnerMsg(int32_t channelType, const uint8_t *data, size_t size, MessageParcel &message)
{
    bool boolParam = (size % 2 == 0) ? true : false;
    int32_t int32Param = *(reinterpret_cast<const int32_t *>(data));
    char *charParam = const_cast<char *>(reinterpret_cast<const char *>(data));

    message.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);

    message.WriteCString(charParam);
    message.WriteInt32(int32Param);
    message.WriteInt32(int32Param);
    message.WriteUint64(size);
    message.WriteInt32(int32Param);

    if (channelType == CHANNEL_TYPE_TCP_DIRECT) {
        message.WriteFileDescriptor(int32Param);
        message.WriteCString(charParam);
    }

    message.WriteBool(boolParam);
    message.WriteBool(boolParam);
    message.WriteBool(boolParam);
    message.WriteInt32(int32Param);
    message.WriteInt32(int32Param);
    message.WriteCString(charParam);
    message.WriteUint32(size);
    message.WriteRawData(data, size);
    message.WriteCString(charParam);
    message.WriteCString(charParam);
    message.WriteInt32(int32Param);

    if (channelType == CHANNEL_TYPE_UDP) {
        message.WriteCString(charParam);
        message.WriteInt32(int32Param);
        message.WriteBool(boolParam);
        if (boolParam) {
            message.WriteInt32(int32Param);
            message.WriteCString(charParam);
        }
    }

    message.WriteInt32(int32Param);
    message.WriteInt32(int32Param);
    message.WriteInt32(int32Param);
    message.WriteInt32(int32Param);
    message.WriteUint32(size);
    message.WriteInt32(int32Param);
    message.WriteInt32(int32Param);
}

bool OnChannelOpenedInnerTest(const uint8_t* data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    MessageParcel dataNomal;
    InitOnChannelOpenedInnerMsg(CHANNEL_TYPE_UNDEFINED, data, size, dataNomal);

    MessageParcel dataTdc;
    InitOnChannelOpenedInnerMsg(CHANNEL_TYPE_TCP_DIRECT, data, size, dataTdc);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_OPENED, dataTdc, reply, option);

    MessageParcel dataUdp;
    InitOnChannelOpenedInnerMsg(CHANNEL_TYPE_UDP, data, size, dataUdp);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_OPENED, dataUdp, reply, option);
    return true;
}

bool OnChannelOpenFailedInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));
    int32_t errCode = *(reinterpret_cast<const int32_t *>(data));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteInt32(errCode);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_OPENFAILED, datas, reply, option);

    return true;
}

bool OnChannelLinkDownInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    char *networkId = const_cast<char *>(reinterpret_cast<const char *>(data));
    int32_t routeType = *(reinterpret_cast<const int32_t *>(data));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;

    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteCString(networkId);
    datas.WriteInt32(routeType);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_LINKDOWN, datas, reply, option);

    return true;
}

bool OnChannelClosedInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));
    int32_t messageType = *(reinterpret_cast<const int32_t *>(data));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteInt32(messageType);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_CLOSED, datas, reply, option);

    return true;
}

bool OnChannelMsgReceivedInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));
    int32_t type = *(reinterpret_cast<const int32_t *>(data));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteUint32(size);
    datas.WriteRawData(data, size);
    datas.WriteInt32(type);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_MSGRECEIVED, datas, reply, option);

    return true;
}

bool OnChannelQosEventInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));
    int32_t eventId = *(reinterpret_cast<const int32_t *>(data));
    WifiChannelQuality wifiChannelInfo = {
        .channel = size,
        .score = size,
    };
    QosTv qosTv = {
        .type = WIFI_CHANNEL_QUALITY,
        .info.wifiChannelInfo = wifiChannelInfo,
    };

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteInt32(eventId);
    datas.WriteInt32(sizeof(qosTv));
    datas.WriteRawData(&qosTv, sizeof(qosTv));
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_QOSEVENT, datas, reply, option);

    return true;
}

bool OnDeviceFoundInnerTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_DISCOVERY_DEVICE_FOUND, datas, reply, option);
    return true;
}

bool OnJoinLNNResultInnerTest(const uint8_t* data, size_t size)
{
    constexpr uint32_t addrTypeLen = 10;
    constexpr int32_t retCode = 2;
    const char* test = "test";
    constexpr size_t len = 4;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteUint32(addrTypeLen);
    datas.WriteInt32(retCode);
    datas.WriteRawData(test, len);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_JOIN_RESULT, datas, reply, option);
    return true;
}

bool OnJoinMetaNodeResultInnerTest(const uint8_t* data, size_t size)
{
    constexpr uint32_t addrTypeLen = 12;
    constexpr int32_t retCode = 2;
    const char* test = "test";
    constexpr size_t len = 4;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteUint32(addrTypeLen);
    datas.WriteInt32(retCode);
    datas.WriteRawData(test, len);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_JOIN_METANODE_RESULT, datas, reply, option);
    return true;
}

bool OnLeaveLNNResultInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t intNum = 2;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteInt32(intNum);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_LEAVE_RESULT, datas, reply, option);
    return true;
}

bool OnLeaveMetaNodeResultInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t intNum = 2;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteInt32(intNum);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_LEAVE_METANODE_RESULT, datas, reply, option);
    return true;
}

bool OnNodeOnlineStateChangedInnerTest(const uint8_t* data, size_t size)
{
    constexpr uint32_t infoTypeLen = 10;
    bool boolNum = true;
    const char* test = "test";
    constexpr size_t len = 4;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteBool(boolNum);
    datas.WriteUint32(infoTypeLen);
    datas.WriteRawData(test, len);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_NODE_ONLINE_STATE_CHANGED, datas, reply, option);
    return true;
}

bool OnNodeBasicInfoChangedInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t type = 2;
    constexpr uint32_t infoTypeLen = 10;
    const char* test = "test";
    constexpr size_t len = 4;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteRawData(test, len);
    datas.WriteInt32(type);
    datas.WriteUint32(infoTypeLen);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_NODE_BASIC_INFO_CHANGED, datas, reply, option);
    return true;
}

bool OnTimeSyncResultInnerTest(const uint8_t* data, size_t size)
{
    constexpr uint32_t infoTypeLen = 10;
    int32_t retCode = *(reinterpret_cast<const char*>(data));
    const char* test = "test";
    constexpr size_t len = 4;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(retCode);
    datas.WriteUint32(infoTypeLen);
    datas.WriteRawData(test, len);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_TIME_SYNC_RESULT, datas, reply, option);
    return true;
}

static bool OnClientEventByReasonAndCode(const uint8_t *data, size_t size, int32_t reason, uint32_t code)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(intNum);
    datas.WriteInt32(reason);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

bool OnPublishLNNResultInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnRefreshLNNResultInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t reason = 8;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_REFRESH_LNN_RESULT);
}

bool OnRefreshDeviceFoundInnerTest(const uint8_t* data, size_t size)
{
    uint32_t deviceLen = *(reinterpret_cast<const int32_t*>(data));
    const char* test = "test";
    MessageParcel datas;
    constexpr size_t len = 4;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteUint32(deviceLen);
    datas.WriteRawData(test, len);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_REFRESH_DEVICE_FOUND, datas, reply, option);
    return true;
}

bool OnClientPermissonChangeInnerTest(const uint8_t* data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    int32_t state = *(reinterpret_cast<const int32_t *>(data));
    char *pkgName = const_cast<char *>(reinterpret_cast<const char *>(data));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(state);
    datas.WriteCString(pkgName);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_PERMISSION_CHANGE, datas, reply, option);

    return true;
}

bool OnDiscoverFailedInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnDiscoverySuccessInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnPublishSuccessInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnPublishFailInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnClientTransLimitChangeInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    uint8_t tos = *(reinterpret_cast<const uint8_t *>(data));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteUint8(tos);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_TRANS_LIMIT_CHANGE, datas, reply, option);

    return true;
}

bool SetChannelInfoInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(data));
    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteCString(sessionName);
    datas.WriteInt32(sessionId);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    softBusClientStub->OnRemoteRequest(CLIENT_SET_CHANNEL_INFO, datas, reply, option);

    return true;
}

bool OnChannelBindInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t *>(data));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_BIND, datas, reply, option);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    /* Validate the length of size */
    if (size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    uint8_t *dataWithEndCharacter = static_cast<uint8_t *>(SoftBusCalloc(size + 1));
    if (dataWithEndCharacter == nullptr) {
        return 0;
    }

    if (memcpy_s(dataWithEndCharacter, size, data, size) != EOK) {
        SoftBusFree(dataWithEndCharacter);
        return 0;
    }

    static OHOS::TestEnv env;
    if (!env.IsInited()) {
        return 0;
    }
    OHOS::OnChannelOpenedInnerTest(dataWithEndCharacter, size);
    OHOS::OnChannelOpenFailedInnerTest(data, size);
    OHOS::OnChannelLinkDownInnerTest(dataWithEndCharacter, size);
    OHOS::OnChannelClosedInnerTest(data, size);
    OHOS::OnChannelMsgReceivedInnerTest(data, size);
    OHOS::OnChannelQosEventInnerTest(data, size);
    OHOS::OnDeviceFoundInnerTest(data, size);
    OHOS::OnJoinLNNResultInnerTest(data, size);
    OHOS::OnJoinMetaNodeResultInnerTest(data, size);
    OHOS::OnLeaveLNNResultInnerTest(data, size);
    OHOS::OnLeaveMetaNodeResultInnerTest(data, size);
    OHOS::OnNodeOnlineStateChangedInnerTest(data, size);
    OHOS::OnNodeBasicInfoChangedInnerTest(data, size);
    OHOS::OnTimeSyncResultInnerTest(data, size);
    OHOS::OnPublishLNNResultInnerTest(data, size);
    OHOS::OnRefreshLNNResultInnerTest(data, size);
    OHOS::OnRefreshDeviceFoundInnerTest(data, size);
    OHOS::OnClientPermissonChangeInnerTest(dataWithEndCharacter, size);
    OHOS::OnDiscoverFailedInnerTest(data, size);
    OHOS::OnDiscoverySuccessInnerTest(data, size);
    OHOS::OnPublishSuccessInnerTest(data, size);
    OHOS::OnPublishFailInnerTest(data, size);
    OHOS::OnClientTransLimitChangeInnerTest(data, size);
    OHOS::SetChannelInfoInnerTest(dataWithEndCharacter, size);
    OHOS::OnChannelBindInnerTest(data, size);

    SoftBusFree(dataWithEndCharacter);
    return 0;
}
