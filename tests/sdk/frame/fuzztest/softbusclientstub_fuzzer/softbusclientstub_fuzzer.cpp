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
#include "softbus_adapter_mem.h"
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

static void InitOnChannelOpenedInnerMsg(int32_t channelType, const uint8_t *data, size_t size, MessageParcel &message)
{
    bool boolParam = (size % 2 == 0) ? true : false;
    int32_t int32Param = *(reinterpret_cast<const int32_t *>(data));
    char *charParam = const_cast<char *>(reinterpret_cast<const char *>(data));

    message.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);

    message.WriteCString(charParam);
    message.WriteInt32(int32Param);
    message.WriteInt32(channelType);
    message.WriteUint64(size);
    message.WriteInt32(int32Param);

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

uint8_t *TestDataSwitch(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return nullptr;
    }
    uint8_t *dataWithEndCharacter = static_cast<uint8_t *>(SoftBusCalloc(size + 1));
    if (dataWithEndCharacter == nullptr) {
        return nullptr;
    }
    if (memcpy_s(dataWithEndCharacter, size, data, size) != EOK) {
        SoftBusFree(dataWithEndCharacter);
        return nullptr;
    }
    return dataWithEndCharacter;
}

/*
 * Due to FileDescriptor is invalid, CHANNEL_TYPE_TCP_DIRECT will read it and crash
 * Do not add test case which channel type is CHANNEL_TYPE_TCP_DIRECT
 */
bool OnChannelOpenedInnerTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return false;
    }
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    MessageParcel dataNomal;
    InitOnChannelOpenedInnerMsg(CHANNEL_TYPE_UNDEFINED, dataWithEndCharacter, size, dataNomal);

    MessageParcel dataUdp;
    InitOnChannelOpenedInnerMsg(CHANNEL_TYPE_UDP, dataWithEndCharacter, size, dataUdp);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_OPENED, dataUdp, reply, option);
    SoftBusFree(dataWithEndCharacter);
    return true;
}

bool OnChannelOpenFailedInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr || data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    DataGenerator::Write(data, size);

    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t errCode = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    GenerateInt32(errCode);

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteInt32(errCode);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_OPENFAILED, datas, reply, option);
    DataGenerator::Clear();

    return true;
}

bool OnChannelLinkDownInnerTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return false;
    }
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    char *networkId = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));
    int32_t routeType = *(reinterpret_cast<const int32_t *>(dataWithEndCharacter));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;

    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteCString(networkId);
    datas.WriteInt32(routeType);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_LINKDOWN, datas, reply, option);
    SoftBusFree(dataWithEndCharacter);

    return true;
}

bool OnChannelClosedInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr || data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    DataGenerator::Write(data, size);

    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t messageType = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    GenerateInt32(messageType);

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteInt32(messageType);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_CLOSED, datas, reply, option);
    DataGenerator::Clear();

    return true;
}

bool OnChannelMsgReceivedInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr || data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    DataGenerator::Write(data, size);

    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t type = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    GenerateInt32(type);

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
    DataGenerator::Clear();

    return true;
}

bool OnChannelQosEventInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr || data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    DataGenerator::Write(data, size);

    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t eventId = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    GenerateInt32(eventId);
    WifiChannelQuality wifiChannelInfo = { 0 };
    GenerateInt32(wifiChannelInfo.channel);
    GenerateInt32(wifiChannelInfo.score);
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
    DataGenerator::Clear();

    return true;
}

bool OnDeviceFoundInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
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

bool OnJoinLNNResultInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr uint32_t addrTypeLen = 10;
    constexpr int32_t retCode = 2;
    const char *test = "test";
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

bool OnJoinMetaNodeResultInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr uint32_t addrTypeLen = 12;
    constexpr int32_t retCode = 2;
    const char *test = "test";
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

bool OnLeaveLNNResultInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
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

bool OnLeaveMetaNodeResultInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
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

bool OnNodeDeviceTrustedChangeInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
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
    softBusClientStub->OnRemoteRequest(CLIENT_ON_NODE_DEVICE_TRUST_CHANGED, datas, reply, option);
    return true;
}

bool OnHichainProofExceptionInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
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
    softBusClientStub->OnRemoteRequest(CLIENT_ON_HICHAIN_PROOF_EXCEPTION, datas, reply, option);
    return true;
}

bool OnNodeOnlineStateChangedInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr uint32_t infoTypeLen = 10;
    bool boolNum = true;
    const char *test = "test";
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

bool OnNodeBasicInfoChangedInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr int32_t type = 2;
    constexpr uint32_t infoTypeLen = 10;
    const char *test = "test";
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

bool OnTimeSyncResultInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr uint32_t infoTypeLen = 10;
    int32_t retCode = *(reinterpret_cast<const char *>(data));
    const char *test = "test";
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
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    int32_t intNum = *(reinterpret_cast<const int32_t *>(data));
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

bool OnPublishLNNResultInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnRefreshLNNResultInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr int32_t reason = 8;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_REFRESH_LNN_RESULT);
}

bool OnRefreshDeviceFoundInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    uint32_t deviceLen = *(reinterpret_cast<const int32_t *>(data));
    const char *test = "test";
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

bool OnClientPermissionChangeInnerTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return false;
    }
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }

    int32_t state = *(reinterpret_cast<const int32_t *>(dataWithEndCharacter));
    char *pkgName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(state);
    datas.WriteCString(pkgName);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_PERMISSION_CHANGE, datas, reply, option);
    SoftBusFree(dataWithEndCharacter);

    return true;
}

bool OnDiscoverFailedInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnDiscoverySuccessInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnPublishSuccessInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnPublishFailInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    constexpr int32_t reason = 2;
    return OnClientEventByReasonAndCode(data, size, reason, CLIENT_ON_PUBLISH_LNN_RESULT);
}

bool OnClientTransLimitChangeInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr || data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    DataGenerator::Write(data, size);

    int32_t channelId = 0;
    uint8_t tos = 0;
    GenerateInt32(channelId);
    GenerateUint8(tos);

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteUint8(tos);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_TRANS_LIMIT_CHANGE, datas, reply, option);
    DataGenerator::Clear();

    return true;
}

bool SetChannelInfoInnerTest(const uint8_t *data, size_t size)
{
    uint8_t *dataWithEndCharacter = TestDataSwitch(data, size);
    if (dataWithEndCharacter == nullptr) {
        return false;
    }
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    DataGenerator::Write(data, size);

    int32_t sessionId = 0;
    int32_t channelId = 0;
    int32_t channelType = 0;
    GenerateInt32(sessionId);
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    char *sessionName = const_cast<char *>(reinterpret_cast<const char *>(dataWithEndCharacter));

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteCString(sessionName);
    datas.WriteInt32(sessionId);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    softBusClientStub->OnRemoteRequest(CLIENT_SET_CHANNEL_INFO, datas, reply, option);
    SoftBusFree(dataWithEndCharacter);
    DataGenerator::Clear();

    return true;
}

bool OnChannelBindInnerTest(const uint8_t *data, size_t size)
{
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr || data == nullptr || size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return false;
    }
    DataGenerator::Write(data, size);

    int32_t channelId = 0;
    int32_t channelType = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_BIND, datas, reply, option);
    DataGenerator::Clear();

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
    OHOS::OnChannelOpenedInnerTest(data, size);
    OHOS::OnChannelOpenFailedInnerTest(data, size);
    OHOS::OnChannelLinkDownInnerTest(data, size);
    OHOS::OnChannelClosedInnerTest(data, size);
    OHOS::OnChannelMsgReceivedInnerTest(data, size);
    OHOS::OnChannelQosEventInnerTest(data, size);
    OHOS::OnDeviceFoundInnerTest(data, size);
    OHOS::OnJoinLNNResultInnerTest(data, size);
    OHOS::OnJoinMetaNodeResultInnerTest(data, size);
    OHOS::OnLeaveLNNResultInnerTest(data, size);
    OHOS::OnLeaveMetaNodeResultInnerTest(data, size);
    OHOS::OnHichainProofExceptionInnerTest(data, size);
    OHOS::OnNodeOnlineStateChangedInnerTest(data, size);
    OHOS::OnNodeBasicInfoChangedInnerTest(data, size);
    OHOS::OnTimeSyncResultInnerTest(data, size);
    OHOS::OnPublishLNNResultInnerTest(data, size);
    OHOS::OnRefreshLNNResultInnerTest(data, size);
    OHOS::OnRefreshDeviceFoundInnerTest(data, size);
    OHOS::OnClientPermissionChangeInnerTest(data, size);
    OHOS::OnDiscoverFailedInnerTest(data, size);
    OHOS::OnDiscoverySuccessInnerTest(data, size);
    OHOS::OnPublishSuccessInnerTest(data, size);
    OHOS::OnPublishFailInnerTest(data, size);
    OHOS::OnClientTransLimitChangeInnerTest(data, size);
    OHOS::SetChannelInfoInnerTest(data, size);
    OHOS::OnChannelBindInnerTest(data, size);
    FuzzedDataProvider provider(data, size);
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
