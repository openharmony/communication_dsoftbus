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
#include "softbus_client_stub.h"
#include "message_parcel.h"
#include "securec.h"

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

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
    CLIENT_ON_TIME_SYNC_RESULT,
    CLIENT_ON_PUBLISH_LNN_RESULT,
    CLIENT_ON_REFRESH_LNN_RESULT,
    CLIENT_ON_REFRESH_DEVICE_FOUND,
    CLIENT_ON_PERMISSION_CHANGE,
};

const std::u16string SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusClient";

bool OnChannelOpenedInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    constexpr size_t len = 4;
    MessageParcel datas;
    bool boolNum = true;
    const char* test = "test";
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(intNum);
    datas.WriteBool(boolNum);
    datas.WriteRawData(test, len);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_OPENED, datas, reply, option);
    return true;
}

bool OnChannelOpenFailedInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    constexpr int32_t channelType = 4;
    constexpr int32_t errCode = 5;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(intNum);
    datas.WriteInt32(channelType);
    datas.WriteInt32(errCode);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_OPENFAILED, datas, reply, option);
    return true;
}

bool OnChannelLinkDownInnerTest(const uint8_t* data, size_t size)
{
    constexpr int32_t intNum = 4;
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
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_LINKDOWN, datas, reply, option);
    return true;
}

bool OnChannelClosedInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    constexpr int32_t channelType = 4;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(intNum);
    datas.WriteInt32(channelType);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_CLOSED, datas, reply, option);
    return true;
}

bool OnChannelMsgReceivedInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    constexpr int32_t channelId = 4;
    constexpr int32_t channelType = 2;
    constexpr uint32_t len = 18;
    constexpr int32_t type = 2;
    constexpr size_t lenStr = 4;
    const char* test = "test";
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteUint32(len);
    datas.WriteRawData(test, lenStr);
    datas.WriteBuffer(data, size);
    datas.WriteInt32(type);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    softBusClientStub->OnRemoteRequest(CLIENT_ON_CHANNEL_MSGRECEIVED, datas, reply, option);
    return true;
}

bool OnChannelQosEventInnerTest(const uint8_t* data, size_t size)
{
    int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
    constexpr int32_t channelType = 3;
    constexpr int32_t eventId = 2;
    constexpr int32_t tvCount = 1;
    constexpr size_t len = 4;
    const char* test = "test";
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteInt32(eventId);
    datas.WriteRawData(test, len);
    datas.WriteInt32(tvCount);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
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

bool OnPublishLNNResultInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    constexpr int32_t reason = 2;
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
    softBusClientStub->OnRemoteRequest(CLIENT_ON_PUBLISH_LNN_RESULT, datas, reply, option);
    return true;
}

bool OnRefreshLNNResultInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    constexpr int32_t reason = 8;
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
    softBusClientStub->OnRemoteRequest(CLIENT_ON_REFRESH_LNN_RESULT, datas, reply, option);
    return true;
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
    softBusClientStub->OnRemoteRequest(CLIENT_ON_PERMISSION_CHANGE, datas, reply, option);
    return true;
}

bool OnDiscoverFailedInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    constexpr int32_t reason = 2;
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
    softBusClientStub->OnRemoteRequest(CLIENT_DISCOVERY_FAIL, datas, reply, option);
    return true;
}

bool OnDiscoverySuccessInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    constexpr int32_t reason = 2;
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
    softBusClientStub->OnRemoteRequest(CLIENT_DISCOVERY_SUCC, datas, reply, option);
    return true;
}

bool OnPublishSuccessInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    constexpr int32_t reason = 2;
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
    softBusClientStub->OnRemoteRequest(CLIENT_PUBLISH_SUCC, datas, reply, option);
    return true;
}

bool OnPublishFailInnerTest(const uint8_t* data, size_t size)
{
    (void)size;
    int32_t intNum = *(reinterpret_cast<const int32_t*>(data));
    constexpr int32_t reason = 2;
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
    softBusClientStub->OnRemoteRequest(CLIENT_PUBLISH_FAIL, datas, reply, option);
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
    OHOS::OnNodeOnlineStateChangedInnerTest(data, size);
    OHOS::OnNodeBasicInfoChangedInnerTest(data, size);
    OHOS::OnTimeSyncResultInnerTest(data, size);
    OHOS::OnPublishLNNResultInnerTest(data, size);
    OHOS::OnRefreshLNNResultInnerTest(data, size);
    OHOS::OnRefreshDeviceFoundInnerTest(data, size);
    OHOS::OnClientPermissonChangeInnerTest(data, size);
    OHOS::OnDiscoverFailedInnerTest(data, size);
    OHOS::OnDiscoverySuccessInnerTest(data, size);
    OHOS::OnPublishSuccessInnerTest(data, size);
    OHOS::OnPublishFailInnerTest(data, size);
    return 0;
}
