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
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_server_frame.h"
#include "system_ability_definition.h"
#include "securec.h"
#define private public
#include "softbus_server_stub.h"
#include "softbus_server.h"

#define TYPE_NUM            10
#define QOS_NUM             8
#define INPUT_NAME_SIZE_MAX 20
#define NETWORKID_SIZE_MAX  20

namespace OHOS {
constexpr int32_t SOFTBUS_FUZZ_TEST_UID = 1;
constexpr int32_t SOFTBUS_FUZZ_TEST_PID = 1;
constexpr int32_t SOFTBUS_FUZZ_TEST_START_DISCOVERY_SUB_SCRIBE_ID = 5;
constexpr int32_t SOFTBUS_FUZZ_TEST_START_DISCOVERY_MODE = 6;
constexpr int32_t SOFTBUS_FUZZ_TEST_START_DISCOVERY_MEDIUM = 7;
constexpr int32_t SOFTBUS_FUZZ_TEST_START_DISCOVERY_FREQ = 8;
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
    SERVER_EVALUATE_QOS = 164,
};

static sptr<IRemoteObject> GetRemoteObject(void)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr != nullptr) {
        return samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    }
    return nullptr;
}

static bool SendRequestByCommand(const uint8_t* data, size_t size, uint32_t command)
{
    sptr<IRemoteObject> object = GetRemoteObject();
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
    return object->SendRequest(command, datas, reply, option) == ERR_NONE;
}

bool PublishServiceFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_PUBLISH_SERVICE);
}

bool UnPublishServiceFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(int32_t)) {
        return false;
    }
    uint32_t offset = 0;
    char pkgname[INPUT_NAME_SIZE_MAX] = "distribdata_test";
    if (memcpy_s(pkgname, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    pkgname[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset = INPUT_NAME_SIZE_MAX;
    int32_t publishId = *reinterpret_cast<const int32_t *>(data + offset);

    MessageParcel datas;
    datas.WriteCString(pkgname);
    datas.WriteInt32(publishId);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->UnpublishServiceInner(datas, reply);
    return true;
}

bool CreateSessionServerFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_CREATE_SESSION_SERVER);
}

bool RemoveSessionServerFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_REMOVE_SESSION_SERVER);
}

bool OpenSessionFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr ||
        size < INPUT_NAME_SIZE_MAX + INPUT_NAME_SIZE_MAX + NETWORKID_SIZE_MAX + NETWORKID_SIZE_MAX + sizeof(bool) +
        sizeof(int32_t)) {
        return false;
    }
    uint32_t offset = 0;
    char sesName[INPUT_NAME_SIZE_MAX] = { 0 };
    char peerSessionName[INPUT_NAME_SIZE_MAX] = { 0 };
    char peerDeviceId[NETWORKID_SIZE_MAX] = { 0 };
    char groupId[NETWORKID_SIZE_MAX] = { 0 };
    if (memcpy_s(sesName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    offset += INPUT_NAME_SIZE_MAX;
    if (memcpy_s(peerSessionName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    offset += INPUT_NAME_SIZE_MAX;
    if (memcpy_s(peerDeviceId, NETWORKID_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        NETWORKID_SIZE_MAX - 1) != EOK) {
        return false;
    }
    offset += NETWORKID_SIZE_MAX;
    if (memcpy_s(groupId, NETWORKID_SIZE_MAX, reinterpret_cast<const char *>(data + offset), NETWORKID_SIZE_MAX - 1) !=
        EOK) {
        return false;
    }
    offset += NETWORKID_SIZE_MAX;
    bool isAsync = *reinterpret_cast<const bool *>(data + offset);
    offset += sizeof(bool);
    int32_t sessionId = *reinterpret_cast<const int32_t *>(data + offset);
    MessageParcel datas;
    datas.WriteCString(sesName);
    datas.WriteCString(peerSessionName);
    datas.WriteCString(peerDeviceId);
    datas.WriteCString(groupId);
    datas.WriteBool(isAsync);
    datas.WriteInt32(sessionId);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->OpenSessionInner(datas, reply);
    return true;
}

bool OpenAuthSessionFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_OPEN_AUTH_SESSION);
}

bool NotifyAuthSuccessFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_NOTIFY_AUTH_SUCCESS);
}

bool CloseChannelFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_CLOSE_CHANNEL);
}

bool SendMessageFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_SESSION_SENDMSG);
}

bool QosReportFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_QOS_REPORT);
}

bool GrantPermissionFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
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

bool RemovePermissionFuzzTest(const uint8_t *data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_REMOVE_PERMISSION);
}

bool StreamStatsFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) + sizeof(int32_t) + sizeof(StreamSendStats)) {
        return false;
    }
    uint32_t offset = 0;
    int32_t channelId = *reinterpret_cast<const int32_t *>(data);
    offset += sizeof(int32_t);
    int32_t channelType = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);

    MessageParcel datas;
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteRawData(data + offset, sizeof(StreamSendStats));
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->StreamStatsInner(datas, reply);
    return true;
}

bool GetSoftbusSpecObjectFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_GET_SOFTBUS_SPEC_OBJECT);
}

bool StartDiscoveryFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
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
    return SendRequestByCommand(data, size, SERVER_STOP_DISCOVERY);
}

bool JoinLNNFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(ConnectionAddr)) {
        return false;
    }
    uint32_t offset = 0;
    char pkgname[INPUT_NAME_SIZE_MAX] = "distribdata_test";
    if (memcpy_s(pkgname, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    pkgname[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    ConnectionAddr *addr = nullptr;
    addr = (ConnectionAddr *)SoftBusCalloc(sizeof(ConnectionAddr));
    if (addr == nullptr) {
        return false;
    }
    if (memcpy_s(addr, sizeof(ConnectionAddr), reinterpret_cast<const char *>(data + offset), sizeof(ConnectionAddr)) !=
        EOK) {
        SoftBusFree(addr);
        return false;
    }

    MessageParcel datas;
    datas.WriteCString(pkgname);
    datas.WriteUint32(sizeof(ConnectionAddr));
    datas.WriteRawData(addr, sizeof(ConnectionAddr));
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        SoftBusFree(addr);
        return false;
    }
    SoftBusServer->JoinLNNInner(datas, reply);
    SoftBusFree(addr);
    return true;
}

bool JoinMetaNodeFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
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

bool LeaveLNNFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + NETWORKID_SIZE_MAX) {
        return false;
    }
    uint32_t offset = 0;
    char pkgname[INPUT_NAME_SIZE_MAX] = "distribdata_test";
    char networkId[NETWORKID_SIZE_MAX] = "123456789asc";

    if (memcpy_s(pkgname, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    pkgname[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    if (memcpy_s(networkId, NETWORKID_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        NETWORKID_SIZE_MAX - 1) != EOK) {
        return false;
    }
    networkId[NETWORKID_SIZE_MAX - 1] = '\0';
    offset += NETWORKID_SIZE_MAX;

    MessageParcel datas;
    datas.WriteCString(pkgname);
    datas.WriteCString(networkId);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->LeaveLNNInner(datas, reply);
    return true;
}

bool LeaveMetaNodeFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_LEAVE_METANODE);
}

bool GetAllOnlineNodeInfoFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(uint32_t)) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "client_test";

    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) !=
        EOK) {
        return false;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    uint32_t infoTypeLen = *reinterpret_cast<const int32_t *>(data + offset);

    MessageParcel datas;
    datas.WriteCString(clientName);
    datas.WriteUint32(infoTypeLen);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->GetAllOnlineNodeInfoInner(datas, reply);
    return true;
}

bool GetLocalDeviceInfoFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(uint32_t)) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "client_test";

    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) !=
        EOK) {
        return false;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    uint32_t infoTypeLen = *reinterpret_cast<const int32_t *>(data + offset);

    MessageParcel datas;
    datas.WriteCString(clientName);
    datas.WriteUint32(infoTypeLen);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->GetLocalDeviceInfoInner(datas, reply);
    return true;
}

bool GetNodeKeyInfoFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr ||
        size < INPUT_NAME_SIZE_MAX + NETWORKID_SIZE_MAX + sizeof(int32_t) + sizeof(uint32_t)) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "client_test";
    char networkId[NETWORKID_SIZE_MAX] = "networkid_test";

    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) !=
        EOK) {
        return false;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    if (memcpy_s(networkId, NETWORKID_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        NETWORKID_SIZE_MAX - 1) != EOK) {
        return false;
    }
    networkId[NETWORKID_SIZE_MAX - 1] = '\0';
    offset += NETWORKID_SIZE_MAX;
    int32_t key = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    uint32_t len = *reinterpret_cast<const uint32_t *>(data + offset);

    MessageParcel datas;
    datas.WriteCString(clientName);
    datas.WriteCString(networkId);
    datas.WriteInt32(key);
    datas.WriteUint32(len);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->GetNodeKeyInfoInner(datas, reply);
    return true;
}

bool SetNodeDataChangeFlagFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + NETWORKID_SIZE_MAX + sizeof(uint16_t)) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "client_test";
    char networkId[NETWORKID_SIZE_MAX] = "networkid_test";

    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) !=
        EOK) {
        return false;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    if (memcpy_s(networkId, NETWORKID_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        NETWORKID_SIZE_MAX - 1) != EOK) {
        return false;
    }
    networkId[NETWORKID_SIZE_MAX - 1] = '\0';
    offset += NETWORKID_SIZE_MAX;
    uint16_t dataChangeFlag = *reinterpret_cast<const uint16_t *>(data + offset);

    MessageParcel datas;
    datas.WriteCString(clientName);
    datas.WriteCString(networkId);
    datas.WriteUint16(dataChangeFlag);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->SetNodeDataChangeFlagInner(datas, reply);
    return true;
}

bool StartTimeSyncFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_START_TIME_SYNC);
}

bool StopTimeSyncFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_STOP_TIME_SYNC);
}

bool PublishLNNFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_PUBLISH_LNN);
}

bool StopPublishLNNFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_STOP_PUBLISH_LNN);
}

bool RefreshLNNFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_REFRESH_LNN);
}

bool StopRefreshLNNFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_STOP_REFRESH_LNN);
}

bool ActiveMetaNodeFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_ACTIVE_META_NODE);
}

bool DeactiveMetaNodeFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_DEACTIVE_META_NODE);
}

bool GetAllMetaNodeInfoFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, SERVER_GET_ALL_META_NODE_INFO);
}

bool ShiftLNNGearFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
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

bool RippleStatsFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) + sizeof(int32_t) + sizeof(TrafficStats)) {
        return false;
    }
    uint32_t offset = 0;
    int32_t channelId = *reinterpret_cast<const uint16_t *>(data);
    offset = sizeof(int32_t);
    int32_t channelType = *reinterpret_cast<const uint16_t *>(data + offset);
    offset += sizeof(int32_t);

    MessageParcel datas;
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteRawData(data + offset, sizeof(TrafficStats));
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->RippleStatsInner(datas, reply);
    return true;
}

bool SoftbusRegisterServiceFuzzTest(const uint8_t* data, size_t size)
{
    return SendRequestByCommand(data, size, MANAGE_REGISTER_SERVICE);
}

bool CheckOpenSessionPermissionFuzzTest(const uint8_t *data, size_t size)
{
#define SESSION_NAME_SIZE_MAX 256
#define DEVICE_ID_SIZE_MAX    50
#define GROUP_ID_SIZE_MAX     50
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < DEVICE_ID_SIZE_MAX + GROUP_ID_SIZE_MAX) {
        return false;
    }
    SetAceessTokenPermission("SoftBusServerStubTest");
    char mySessionName[SESSION_NAME_SIZE_MAX] = "com.test.trans.session";
    char peerSessionName[SESSION_NAME_SIZE_MAX] = "com.test.trans.session.sendfile";
    char peerDeviceId[DEVICE_ID_SIZE_MAX] = "com.test.trans.session.sendfile";
    char groupId[GROUP_ID_SIZE_MAX] = "com.test.trans.session.sendfile";

    if (memcpy_s(peerDeviceId, DEVICE_ID_SIZE_MAX, reinterpret_cast<const char *>(data), DEVICE_ID_SIZE_MAX - 1) !=
        EOK) {
        return false;
    }
    peerDeviceId[DEVICE_ID_SIZE_MAX - 1] = '\0';

    if (memcpy_s(groupId, GROUP_ID_SIZE_MAX, reinterpret_cast<const char *>(data + DEVICE_ID_SIZE_MAX),
        GROUP_ID_SIZE_MAX - 1) != EOK) {
        return false;
    }
    groupId[GROUP_ID_SIZE_MAX - 1] = '\0';
    SessionAttribute attr;
    attr.dataType = 1;
    attr.linkTypeNum = 0;
    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerDeviceId,
        .groupId = groupId,
        .attr = &attr,
    };
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->CheckOpenSessionPermission(&param);
    return true;
}

bool EvaLuateQosInnerFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    int32_t dataTypeNum = size % TYPE_NUM;
    uint32_t qosCount = size % QOS_NUM;

    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteCString("6B97BC8F6F85A2A1A6E0E262111F42D6A8541CBFF6CAF688FA5293956EC3FD43");

    datas.WriteInt32(dataTypeNum);
    datas.WriteUint32(qosCount);
    datas.WriteBuffer(data, qosCount);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_EVALUATE_QOS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool EvaLuateQosInnerNetworkIdFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    int32_t dataTypeNum = size % TYPE_NUM;
    uint32_t qosCount = size % QOS_NUM;

    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteCString((const char *)data);

    datas.WriteInt32(dataTypeNum);
    datas.WriteUint32(qosCount);
    datas.WriteBuffer(data, qosCount);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_EVALUATE_QOS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool EvaLuateQosInnerDataTypeFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    uint32_t qosCount = size % QOS_NUM;

    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteCString("6B97BC8F6F85A2A1A6E0E262111F42D6A8541CBFF6CAF688FA5293956EC3FD43");

    datas.WriteInt32(size);
    datas.WriteUint32(qosCount);
    datas.WriteBuffer(data, qosCount);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_EVALUATE_QOS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool EvaLuateQosInnerQosCountFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr) {
        return false;
    }
    MessageParcel datas;
    int32_t dataTypeNum = size % TYPE_NUM;
    datas.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    datas.WriteCString("6B97BC8F6F85A2A1A6E0E262111F42D6A8541CBFF6CAF688FA5293956EC3FD43");

    datas.WriteInt32(dataTypeNum);
    datas.WriteUint32(size);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    SetAceessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_EVALUATE_QOS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool RunFuzzTestCase(const uint8_t* data, size_t size)
{
    OHOS::EvaLuateQosInnerDataTypeFuzzTest(data, size);
    OHOS::EvaLuateQosInnerQosCountFuzzTest(data, size);
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
    OHOS::CheckOpenSessionPermissionFuzzTest(data, size);
    OHOS::EvaLuateQosInnerFuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* ptr, size_t size)
{
    if (size == 0 || size >= INT32_MAX - 1) {
        return 0;
    }
    OHOS::RunFuzzTestCase(ptr, size);
    uint8_t *data = (uint8_t *)SoftBusCalloc(size + 1);
    if (data == nullptr) {
        return 0;
    }
    if (memcpy_s(data, size, ptr, size) != EOK) {
        SoftBusFree(data);
        return 0;
    }
    OHOS::EvaLuateQosInnerNetworkIdFuzzTest(data, size);
    SoftBusFree(data);
    return 0;
}
