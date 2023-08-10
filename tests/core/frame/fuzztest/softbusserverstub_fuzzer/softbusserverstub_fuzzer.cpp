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

#include "softbusserverstub_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "message_option.h"
#include "message_parcel.h"
#include "softbus_access_token_test.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_server.h"
#include "softbus_server_frame.h"
#include "system_ability_definition.h"

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t SOFTBUS_FUZZ_TEST_CHANNEL_ID = 3;
constexpr int32_t SOFTBUS_FUZZ_TEST_CHANNEL_TYPE = 4;
constexpr int32_t SOFTBUS_FUZZ_TEST_INFO_TYPE_LEN = 196;

const std::u16string SOFTBUS_SERVER_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusServer";

enum SoftBusFuncId {
    SERVER_PUBLISH_SERVICE = 128,
    SERVER_UNPUBLISH_SERVICE,
    SERVER_CREATE_SESSION_SERVER,
    SERVER_REMOVE_SESSION_SERVER,
    SERVER_OPEN_SESSION,
    SERVER_OPEN_AUTH_SESSION,
    SERVER_NOTIFY_AUTH_SUCCESS,
    SERVER_CLOSE_CHANNEL,
    SERVER_SESSION_SENDMSG,
    SERVER_QOS_REPORT,
    SERVER_GRANT_PERMISSION,
    SERVER_REMOVE_PERMISSION,
    SERVER_STREAM_STATS,
    SERVER_GET_SOFTBUS_SPEC_OBJECT,
    SERVER_START_DISCOVERY,
    SERVER_STOP_DISCOVERY,
    SERVER_JOIN_LNN,
    SERVER_JOIN_METANODE,
    SERVER_LEAVE_LNN,
    SERVER_LEAVE_METANODE,
    SERVER_GET_ALL_ONLINE_NODE_INFO,
    SERVER_GET_LOCAL_DEVICE_INFO,
    SERVER_GET_NODE_KEY_INFO,
    SERVER_SET_NODE_DATA_CHANGE_FLAG,
    SERVER_START_TIME_SYNC,
    SERVER_STOP_TIME_SYNC,
    SERVER_PUBLISH_LNN,
    SERVER_STOP_PUBLISH_LNN,
    SERVER_REFRESH_LNN,
    SERVER_STOP_REFRESH_LNN,
    SERVER_ACTIVE_META_NODE,
    SERVER_DEACTIVE_META_NODE,
    SERVER_GET_ALL_META_NODE_INFO,
    SERVER_SHIFT_LNN_GEAR,
    SERVER_RIPPLE_STATS,
};

sptr<OHOS::SoftBusServer> g_softBusServer = nullptr;

bool PublishServiceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_PUBLISH_SERVICE, datas, reply, option);
    return true;
}

bool UnPublishServiceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_UNPUBLISH_SERVICE, datas, reply, option);
    return true;
}

bool NotifyAuthSuccessFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_NOTIFY_AUTH_SUCCESS, datas, reply, option);
    return true;
}

bool CloseChannelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_CLOSE_CHANNEL, datas, reply, option);
    return true;
}

bool QosReportFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_QOS_REPORT, datas, reply, option);
    return true;
}

bool StreamStatsFuzzTest(const uint8_t* data, size_t size)
{
    int32_t channelId = SOFTBUS_FUZZ_TEST_CHANNEL_ID;
    int32_t channelType = SOFTBUS_FUZZ_TEST_CHANNEL_TYPE;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteRawData(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_STREAM_STATS, datas, reply, option);
    return true;
}

bool GetSoftbusSpecObjectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_GET_SOFTBUS_SPEC_OBJECT, datas, reply, option);
    return true;
}

bool StopDiscoveryFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_STOP_DISCOVERY, datas, reply, option);
    return true;
}

bool LeaveLNNFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_LEAVE_LNN, datas, reply, option);
    return true;
}

bool LeaveMetaNodeFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_LEAVE_METANODE, datas, reply, option);
    return true;
}

bool GetAllOnlineNodeInfoFuzzTest(const uint8_t* data, size_t size)
{
    (void)size;
    uint32_t infoTypeLen = SOFTBUS_FUZZ_TEST_INFO_TYPE_LEN;
    const char* charStr = reinterpret_cast<const char*>(data);
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteCString(charStr);
    datas.WriteUint32(infoTypeLen);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_GET_ALL_ONLINE_NODE_INFO, datas, reply, option);
    return true;
}

bool GetLocalDeviceInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_GET_LOCAL_DEVICE_INFO, datas, reply, option);
    return true;
}

bool GetNodeKeyInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_GET_NODE_KEY_INFO, datas, reply, option);
    return true;
}

bool SetNodeDataChangeFlagFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_SET_NODE_DATA_CHANGE_FLAG, datas, reply, option);
    return true;
}

bool StartTimeSyncFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_START_TIME_SYNC, datas, reply, option);
    return true;
}

bool StopTimeSyncFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_STOP_TIME_SYNC, datas, reply, option);
    return true;
}

bool PublishLNNFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_PUBLISH_LNN, datas, reply, option);
    return true;
}

bool StopPublishLNNFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_STOP_PUBLISH_LNN, datas, reply, option);
    return true;
}

bool RefreshLNNFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_REFRESH_LNN, datas, reply, option);
    return true;
}

bool StopRefreshLNNFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_STOP_REFRESH_LNN, datas, reply, option);
    return true;
}

bool GetAllMetaNodeInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_GET_ALL_META_NODE_INFO, datas, reply, option);
    return true;
}

bool RippleStatsFuzzTest(const uint8_t* data, size_t size)
{
    int32_t channelId = SOFTBUS_FUZZ_TEST_CHANNEL_ID;
    int32_t channelType = SOFTBUS_FUZZ_TEST_CHANNEL_TYPE;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteRawData(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    if (g_softBusServer == nullptr) {
        g_softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        InitTransStatisticSysEvt();
        InitSoftBusServer();
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    g_softBusServer->OnRemoteRequest(SERVER_RIPPLE_STATS, datas, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    if (size == 0 || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    OHOS::PublishServiceFuzzTest(data, size);
    OHOS::UnPublishServiceFuzzTest(data, size);
    OHOS::NotifyAuthSuccessFuzzTest(data, size);
    OHOS::CloseChannelFuzzTest(data, size);
    OHOS::QosReportFuzzTest(data, size);
    OHOS::StreamStatsFuzzTest(data, size);
    OHOS::GetSoftbusSpecObjectFuzzTest(data, size);
    OHOS::StopDiscoveryFuzzTest(data, size);
    OHOS::LeaveLNNFuzzTest(data, size);
    OHOS::LeaveMetaNodeFuzzTest(data, size);
    OHOS::GetAllOnlineNodeInfoFuzzTest(data, size);
    OHOS::GetLocalDeviceInfoFuzzTest(data, size);
    OHOS::GetNodeKeyInfoFuzzTest(data, size);
    OHOS::SetNodeDataChangeFlagFuzzTest(data, size);
    OHOS::StartTimeSyncFuzzTest(data, size);
    OHOS::StopTimeSyncFuzzTest(data, size);
    OHOS::PublishLNNFuzzTest(data, size);
    OHOS::StopPublishLNNFuzzTest(data, size);
    OHOS::RefreshLNNFuzzTest(data, size);
    OHOS::StopRefreshLNNFuzzTest(data, size);
    OHOS::GetAllMetaNodeInfoFuzzTest(data, size);
    OHOS::RippleStatsFuzzTest(data, size);
    return 0;
}

