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
#include "iservice_registry.h"
#include "message_option.h"
#include "message_parcel.h"
#include "rpc_errno.h"
#include "softbus_access_token_test.h"
#include "softbus_error_code.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_server.h"
#include "softbus_server_frame.h"
#include "system_ability_definition.h"

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t SOFTBUS_FUZZ_TEST_UID = 1;
constexpr int32_t SOFTBUS_FUZZ_TEST_PID = 1;
constexpr int32_t SOFTBUS_FUZZ_TEST_CHANNEL_ID = 3;
constexpr int32_t SOFTBUS_FUZZ_TEST_CHANNEL_TYPE = 4;
constexpr int32_t SOFTBUS_FUZZ_TEST_START_DISCOVERY_SUB_SCRIBE_ID = 5;
constexpr int32_t SOFTBUS_FUZZ_TEST_START_DISCOVERY_MODE = 6;
constexpr int32_t SOFTBUS_FUZZ_TEST_START_DISCOVERY_MEDIUM = 7;
constexpr int32_t SOFTBUS_FUZZ_TEST_START_DISCOVERY_FREQ = 8;
constexpr int32_t SOFTBUS_FUZZ_TEST_INFO_TYPE_LEN = 196;
constexpr int32_t SOFTBUS_FUZZ_TEST_ADDR_TYPE_LEN = 160;

const std::u16string SOFTBUS_SERVER_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusServer";
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";

enum SoftBusFuncId {
    MANAGE_REGISTER_SERVICE = 0,
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

bool PublishServiceFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_PUBLISH_SERVICE, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool UnPublishServiceFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_UNPUBLISH_SERVICE, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool CreateSessionServerFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_CREATE_SESSION_SERVER, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool RemoveSessionServerFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_REMOVE_SESSION_SERVER, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool OpenSessionFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_OPEN_SESSION, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool OpenAuthSessionFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_OPEN_AUTH_SESSION, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool NotifyAuthSuccessFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_NOTIFY_AUTH_SUCCESS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool CloseChannelFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_CLOSE_CHANNEL, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool SendMessageFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_SESSION_SENDMSG, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool QosReportFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_QOS_REPORT, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool GrantPermissionFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    int32_t uid = SOFTBUS_FUZZ_TEST_UID;
    int32_t pid = SOFTBUS_FUZZ_TEST_PID;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteInt32(uid);
    datas.WriteInt32(pid);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_GRANT_PERMISSION, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool RemovePermissionFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_REMOVE_PERMISSION, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool StreamStatsFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
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
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_STREAM_STATS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool GetSoftbusSpecObjectFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_GET_SOFTBUS_SPEC_OBJECT, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool StartDiscoveryFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    int32_t subscribeId = SOFTBUS_FUZZ_TEST_START_DISCOVERY_SUB_SCRIBE_ID;
    int32_t mode = SOFTBUS_FUZZ_TEST_START_DISCOVERY_MODE;
    int32_t medium = SOFTBUS_FUZZ_TEST_START_DISCOVERY_MEDIUM;
    int32_t freq = SOFTBUS_FUZZ_TEST_START_DISCOVERY_FREQ;
    bool boolNum = true;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteInt32(subscribeId);
    datas.WriteInt32(mode);
    datas.WriteInt32(medium);
    datas.WriteInt32(freq);
    datas.WriteBool(boolNum);
    datas.WriteInt32(freq);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_START_DISCOVERY, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool StopDiscoveryFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_STOP_DISCOVERY, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool JoinLNNFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    uint32_t addrTypeLen = SOFTBUS_FUZZ_TEST_ADDR_TYPE_LEN;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteUint32(addrTypeLen);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_JOIN_LNN, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool JoinMetaNodeFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    uint32_t addrTypeLen = SOFTBUS_FUZZ_TEST_ADDR_TYPE_LEN;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteUint32(addrTypeLen);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_JOIN_METANODE, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool LeaveLNNFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_LEAVE_LNN, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool LeaveMetaNodeFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_LEAVE_METANODE, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool GetAllOnlineNodeInfoFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    uint32_t infoTypeLen = SOFTBUS_FUZZ_TEST_INFO_TYPE_LEN;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteUint32(infoTypeLen);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_GET_ALL_ONLINE_NODE_INFO, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool GetLocalDeviceInfoFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_GET_LOCAL_DEVICE_INFO, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool GetNodeKeyInfoFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_GET_NODE_KEY_INFO, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool SetNodeDataChangeFlagFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_SET_NODE_DATA_CHANGE_FLAG, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool StartTimeSyncFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_START_TIME_SYNC, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool StopTimeSyncFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_STOP_TIME_SYNC, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool PublishLNNFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_PUBLISH_LNN, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool StopPublishLNNFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_STOP_PUBLISH_LNN, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool RefreshLNNFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_REFRESH_LNN, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool StopRefreshLNNFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_STOP_REFRESH_LNN, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool ActiveMetaNodeFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteRawData(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_ACTIVE_META_NODE, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool DeactiveMetaNodeFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_DEACTIVE_META_NODE, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool GetAllMetaNodeInfoFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_GET_ALL_META_NODE_INFO, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool ShiftLNNGearFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    bool boolNum = true;
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.WriteBool(boolNum);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_SHIFT_LNN_GEAR, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool RippleStatsFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
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
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_RIPPLE_STATS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool SoftbusRegisterServiceFuzzTest(const uint8_t* data, size_t size)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(MANAGE_REGISTER_SERVICE, datas, reply, option) != ERR_NONE) {
        return false;
    }
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

    if (size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    OHOS::OpenSessionFuzzTest(data, size);
    OHOS::OpenAuthSessionFuzzTest(data, size);
    OHOS::CreateSessionServerFuzzTest(data, size);
    OHOS::RemoveSessionServerFuzzTest(data, size);
    OHOS::NotifyAuthSuccessFuzzTest(data, size);
    OHOS::CloseChannelFuzzTest(data, size);
    OHOS::SendMessageFuzzTest(data, size);
    OHOS::QosReportFuzzTest(data, size);
    OHOS::GrantPermissionFuzzTest(data, size);
    OHOS::RemovePermissionFuzzTest(data, size);
    OHOS::StreamStatsFuzzTest(data, size);
    OHOS::GetSoftbusSpecObjectFuzzTest(data, size);
    OHOS::StartDiscoveryFuzzTest(data, size);
    OHOS::StopDiscoveryFuzzTest(data, size);
    OHOS::JoinLNNFuzzTest(data, size);
    OHOS::JoinMetaNodeFuzzTest(data, size);
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
    OHOS::ActiveMetaNodeFuzzTest(data, size);
    OHOS::DeactiveMetaNodeFuzzTest(data, size);
    OHOS::GetAllMetaNodeInfoFuzzTest(data, size);
    OHOS::ShiftLNNGearFuzzTest(data, size);
    OHOS::RippleStatsFuzzTest(data, size);
    OHOS::PublishServiceFuzzTest(data, size);
    OHOS::UnPublishServiceFuzzTest(data, size);
    OHOS::SoftbusRegisterServiceFuzzTest(data, size);
    return 0;
}

