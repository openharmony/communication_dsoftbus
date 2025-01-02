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
#include "softbus_access_token_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_server_frame.h"
#include "system_ability_definition.h"
#include "securec.h"
#define private public
#include "softbus_def.h"
#include "softbus_server_stub.h"
#include "softbus_server.h"

#define TYPE_NUM            10
#define QOS_NUM             8
#define INPUT_NAME_SIZE_MAX 70
#define NETWORKID_SIZE_MAX  20

#define SIZE_NUM_THREE 3
#define SIZE_NUM_FOUR 4
#define SIZE_NUM_FIVE 5

namespace OHOS {
constexpr int32_t SOFTBUS_FUZZ_TEST_ADDR_TYPE_LEN = 160;

const std::u16string SOFTBUS_SERVER_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusServer";
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";

enum SoftBusFuncId {
    MANAGE_REGISTER_SERVICE = 0,
    SERVER_CREATE_SESSION_SERVER = 128,
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

static bool SendRequestByCommand(const uint8_t *data, size_t size, uint32_t command)
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
    SetAccessTokenPermission("SoftBusServerStubTest");
    return object->SendRequest(command, datas, reply, option) == ERR_NONE;
}

bool CreateSessionServerFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + INPUT_NAME_SIZE_MAX ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char pkgName[INPUT_NAME_SIZE_MAX] = "distribdata_test";
    if (memcpy_s(pkgName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    pkgName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset = INPUT_NAME_SIZE_MAX;
    char sessionName[INPUT_NAME_SIZE_MAX] = "distribdata_test";
    if (memcpy_s(sessionName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    sessionName[INPUT_NAME_SIZE_MAX - 1] = '\0';

    MessageParcel datas;
    datas.WriteCString(pkgName);
    datas.WriteCString(sessionName);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->CreateSessionServerInner(datas, reply);
    return true;
}

bool RemoveSessionServerFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + INPUT_NAME_SIZE_MAX ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char pkgName[INPUT_NAME_SIZE_MAX] = "distribdata_test";
    if (memcpy_s(pkgName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    pkgName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset = INPUT_NAME_SIZE_MAX;
    char sessionName[INPUT_NAME_SIZE_MAX] = "distribdata_test";
    if (memcpy_s(sessionName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    sessionName[INPUT_NAME_SIZE_MAX - 1] = '\0';

    MessageParcel datas;
    datas.WriteCString(pkgName);
    datas.WriteCString(sessionName);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->RemoveSessionServerInner(datas, reply);
    return true;
}

bool OpenSessionFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size >= INT32_MAX - 1 ||
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

bool OpenAuthSessionFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(ConnectionAddr) + INPUT_NAME_SIZE_MAX ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char sessionName[INPUT_NAME_SIZE_MAX] = { 0 };
    if (memcpy_s(sessionName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    sessionName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    ConnectionAddr addrInfo;
    memset_s(&addrInfo, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    if (memcpy_s(&addrInfo, sizeof(ConnectionAddr), data + offset, sizeof(ConnectionAddr)) != EOK) {
        return false;
    }
    MessageParcel datas;
    datas.WriteCString(sessionName);
    datas.WriteRawData(&addrInfo, sizeof(ConnectionAddr));
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->OpenAuthSessionInner(datas, reply);
    return true;
}

bool NotifyAuthSuccessFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) + sizeof(int32_t) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    int32_t channelId = *reinterpret_cast<const int32_t *>(data);
    offset += sizeof(int32_t);
    int32_t channelType = *reinterpret_cast<const int32_t *>(data + offset);

    MessageParcel datas;
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->NotifyAuthSuccessInner(datas, reply);
    return true;
}

bool CloseChannelFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) + sizeof(int32_t) + INPUT_NAME_SIZE_MAX ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    int32_t channelId = *reinterpret_cast<const int32_t *>(data);
    offset += sizeof(int32_t);
    int32_t channelType = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    char sessionName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(sessionName, INPUT_NAME_SIZE_MAX, data + offset, INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    sessionName[INPUT_NAME_SIZE_MAX - 1] = '\0';

    MessageParcel datas;
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    if (channelType == CHANNEL_TYPE_UNDEFINED) {
        datas.WriteCString(sessionName);
    }
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->CloseChannelInner(datas, reply);
    return true;
}

bool SendMessageFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) * SIZE_NUM_THREE +
        INPUT_NAME_SIZE_MAX + INPUT_NAME_SIZE_MAX + sizeof(uint32_t) || size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    int32_t channelId = *reinterpret_cast<const int32_t *>(data);
    offset += sizeof(int32_t);
    int32_t channelType = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    uint32_t len = INPUT_NAME_SIZE_MAX;
    char sessionName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(sessionName, INPUT_NAME_SIZE_MAX, data + offset, INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    sessionName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    char msg[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(msg, INPUT_NAME_SIZE_MAX, data + offset, INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    msg[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    int32_t msgType = *reinterpret_cast<const int32_t *>(data + offset);
    MessageParcel datas;
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteUint32(len);
    datas.WriteRawData(msg, INPUT_NAME_SIZE_MAX);
    datas.WriteInt32(msgType);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->SendMessageInner(datas, reply);
    return true;
}

bool QosReportFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) * SIZE_NUM_FOUR ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    int32_t channelId = *reinterpret_cast<const int32_t *>(data);
    offset += sizeof(int32_t);
    int32_t channelType = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t appType = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t quality = *reinterpret_cast<const int32_t *>(data + offset);
    MessageParcel datas;
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    datas.WriteInt32(appType);
    datas.WriteInt32(quality);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->QosReportInner(datas, reply);
    return true;
}

bool GrantPermissionFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) + sizeof(int32_t) +
        INPUT_NAME_SIZE_MAX + INPUT_NAME_SIZE_MAX + sizeof(int32_t) || size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    int32_t uid = *reinterpret_cast<const int32_t *>(data);
    offset += sizeof(int32_t);
    int32_t pid = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    char sessionName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(sessionName, INPUT_NAME_SIZE_MAX, data, INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    sessionName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    char msg[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(msg, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    msg[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    int32_t msgType = *reinterpret_cast<const int32_t *>(data + offset);
    MessageParcel datas;
    datas.WriteInt32(uid);
    datas.WriteInt32(pid);
    datas.WriteCString(sessionName);
    datas.WriteInt32(msgType);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->SendMessageInner(datas, reply);
    return true;
}

bool RemovePermissionFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX || size >= INT32_MAX - 1) {
        return false;
    }
    char sessionName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(sessionName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    sessionName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    MessageParcel datas;
    datas.WriteCString(sessionName);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->RemovePermissionInner(datas, reply);
    return true;
}

bool StreamStatsFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) + sizeof(int32_t) + sizeof(StreamSendStats) ||
        size >= INT32_MAX - 1) {
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

bool GetSoftbusSpecObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0 || size >= INT32_MAX - 1) {
        return false;
    }
    return SendRequestByCommand(data, size, SERVER_GET_SOFTBUS_SPEC_OBJECT);
}

bool JoinLNNFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(ConnectionAddr) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char pkgName[INPUT_NAME_SIZE_MAX] = "distribdata_test";
    if (memcpy_s(pkgName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    pkgName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    ConnectionAddr *addr = nullptr;
    addr = (ConnectionAddr *)SoftBusCalloc(sizeof(ConnectionAddr));
    if (addr == nullptr) {
        return false;
    }
    if (memcpy_s(addr, sizeof(ConnectionAddr), reinterpret_cast<const char *>(data + offset),
        sizeof(ConnectionAddr)) != EOK) {
        SoftBusFree(addr);
        return false;
    }

    MessageParcel datas;
    datas.WriteCString(pkgName);
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

bool JoinMetaNodeFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size == 0 || size >= INT32_MAX - 1) {
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
    SetAccessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_JOIN_METANODE, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool LeaveLNNFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + NETWORKID_SIZE_MAX ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char pkgName[INPUT_NAME_SIZE_MAX] = "distribdata_test";
    char networkId[NETWORKID_SIZE_MAX] = "123456789asc";

    if (memcpy_s(pkgName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    pkgName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    if (memcpy_s(networkId, NETWORKID_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        NETWORKID_SIZE_MAX - 1) != EOK) {
        return false;
    }
    networkId[NETWORKID_SIZE_MAX - 1] = '\0';
    offset += NETWORKID_SIZE_MAX;

    MessageParcel datas;
    datas.WriteCString(pkgName);
    datas.WriteCString(networkId);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->LeaveLNNInner(datas, reply);
    return true;
}

bool LeaveMetaNodeFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0 || size >= INT32_MAX - 1) {
        return false;
    }
    return SendRequestByCommand(data, size, SERVER_LEAVE_METANODE);
}

bool GetAllOnlineNodeInfoFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(uint32_t) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "client-test";

    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) !=
        EOK) {
        return false;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    uint32_t infoTypeLen = *reinterpret_cast<const uint32_t *>(data + offset);

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

bool GetLocalDeviceInfoFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(uint32_t) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "client-test";

    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) !=
        EOK) {
        return false;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    uint32_t infoTypeLen = *reinterpret_cast<const uint32_t *>(data + offset);

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
    if (object == nullptr || data == nullptr || size >= INT32_MAX - 1 ||
        size < INPUT_NAME_SIZE_MAX + NETWORKID_SIZE_MAX + sizeof(int32_t) + sizeof(uint32_t)) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "client-test";
    char networkId[NETWORKID_SIZE_MAX] = "networkid-test";

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
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + NETWORKID_SIZE_MAX + sizeof(uint16_t) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "client-test";
    char networkId[NETWORKID_SIZE_MAX] = "networkid-test";

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

bool StartTimeSyncFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + NETWORKID_SIZE_MAX +
        sizeof(int32_t) + sizeof(int32_t) || size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "";
    char networkId[NETWORKID_SIZE_MAX] = "";

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
    int32_t accuracy = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t period = *reinterpret_cast<const int32_t *>(data + offset);

    MessageParcel datas;
    datas.WriteCString(clientName);
    datas.WriteCString(networkId);
    datas.WriteInt32(accuracy);
    datas.WriteInt32(period);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->StartTimeSyncInner(datas, reply);
    return true;
}

bool StopTimeSyncFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + NETWORKID_SIZE_MAX +
        sizeof(int32_t) + sizeof(int32_t) || size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "";
    char networkId[NETWORKID_SIZE_MAX] = "";

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

    MessageParcel datas;
    datas.WriteCString(clientName);
    datas.WriteCString(networkId);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->StartTimeSyncInner(datas, reply);
    return true;
}

static void DiscInfoProc(const uint8_t *data, MessageParcel &datas)
{
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) !=
        EOK) {
        return;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    char capability[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(capability, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return;
    }
    capability[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    int32_t publishId = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t mode = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t medium = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t freq = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t dataLen = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    char capabilityData[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(capabilityData, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return;
    }
    capabilityData[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    bool ranging = *reinterpret_cast<const bool *>(data + offset);

    datas.WriteCString(clientName);
    datas.WriteInt32(publishId);
    datas.WriteInt32(mode);
    datas.WriteInt32(medium);
    datas.WriteInt32(freq);
    datas.WriteCString(capability);
    datas.WriteInt32(dataLen);
    datas.WriteCString(capabilityData);
    datas.WriteBool(ranging);
}

bool PublishLNNFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < (INPUT_NAME_SIZE_MAX * SIZE_NUM_THREE) +
        (sizeof(int32_t) * SIZE_NUM_FIVE) + sizeof(bool) || size >= INT32_MAX - 1) {
        return false;
    }
    MessageParcel datas;
    DiscInfoProc(data, datas);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->PublishLNNInner(datas, reply);
    return true;
}

bool StopPublishLNNFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(int32_t) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    int32_t publishId = *reinterpret_cast<const int32_t *>(data + offset);
    MessageParcel datas;
    datas.WriteCString(clientName);
    datas.WriteInt32(publishId);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->StopPublishLNNInner(datas, reply);
    return true;
}

static void RefreshInfoProc(const uint8_t *data, MessageParcel &datas)
{
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data), INPUT_NAME_SIZE_MAX - 1) !=
        EOK) {
        return;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    char capability[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(capability, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return;
    }
    capability[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    int32_t publishId = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t mode = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t medium = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t freq = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    int32_t dataLen = *reinterpret_cast<const int32_t *>(data + offset);
    offset += sizeof(int32_t);
    bool isSameAccount = *reinterpret_cast<const bool *>(data + offset);
    offset += sizeof(bool);
    bool isWakeRemote = *reinterpret_cast<const bool *>(data + offset);
    offset += sizeof(bool);
    char capabilityData[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(capabilityData, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return;
    }
    capabilityData[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;

    datas.WriteCString(clientName);
    datas.WriteInt32(publishId);
    datas.WriteInt32(mode);
    datas.WriteInt32(medium);
    datas.WriteInt32(freq);
    datas.WriteBool(isSameAccount);
    datas.WriteBool(isWakeRemote);
    datas.WriteCString(capability);
    datas.WriteInt32(dataLen);
    datas.WriteCString(capabilityData);
}

bool RefreshLNNFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < (INPUT_NAME_SIZE_MAX * SIZE_NUM_THREE) +
        (sizeof(int32_t) * SIZE_NUM_FIVE) + sizeof(bool) + sizeof(bool) || size >= INT32_MAX - 1) {
        return false;
    }
    MessageParcel datas;
    RefreshInfoProc(data, datas);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->RefreshLNNInner(datas, reply);
    return true;
}

bool StopRefreshLNNFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(int32_t) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    char clientName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(clientName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    clientName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    int32_t refreshId = *reinterpret_cast<const int32_t *>(data + offset);
    MessageParcel datas;
    datas.WriteCString(clientName);
    datas.WriteInt32(refreshId);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->StopRefreshLNNInner(datas, reply);
    return true;
}

bool ActiveMetaNodeFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(MetaNodeConfigInfo) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    MetaNodeConfigInfo info;
    if (memset_s(&info, sizeof(MetaNodeConfigInfo), 0, sizeof(MetaNodeConfigInfo)) != EOK) {
        return false;
    }
    if (memcpy_s(&info, sizeof(MetaNodeConfigInfo), reinterpret_cast<const MetaNodeConfigInfo *>(data),
        sizeof(MetaNodeConfigInfo)) != EOK) {
        return false;
    }
    MessageParcel datas;
    datas.WriteRawData(&info, sizeof(MetaNodeConfigInfo));
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->ActiveMetaNodeInner(datas, reply);
    return true;
}

bool DeactiveMetaNodeFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX ||
        size >= INT32_MAX - 1) {
        return false;
    }
    char metaNodeId[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(metaNodeId, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    metaNodeId[INPUT_NAME_SIZE_MAX - 1] = '\0';
    MessageParcel datas;
    datas.WriteCString(metaNodeId);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->DeactiveMetaNodeInner(datas, reply);
    return true;
}

bool GetAllMetaNodeInfoFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) || size >= INT32_MAX - 1) {
        return false;
    }
    int32_t infoNum = *reinterpret_cast<const int32_t *>(data);
    MessageParcel datas;
    datas.WriteInt32(infoNum);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->GetAllMetaNodeInfoInner(datas, reply);
    return true;
}

static void ShiftLNNGearInfoProc(const uint8_t *data, MessageParcel &datas)
{
    uint32_t offset = 0;
    char pkgName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(pkgName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return;
    }
    pkgName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    datas.WriteCString(pkgName);
    char callerId[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(callerId, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return;
    }
    callerId[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    datas.WriteCString(callerId);
    bool hasNetworkId = *reinterpret_cast<const bool *>(data + offset);
    datas.WriteBool(hasNetworkId);
    offset += sizeof(bool);
    if (!hasNetworkId) {
        char networkId[INPUT_NAME_SIZE_MAX] = "";
        if (memcpy_s(networkId, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
            INPUT_NAME_SIZE_MAX - 1) != EOK) {
            return;
        }
        networkId[INPUT_NAME_SIZE_MAX - 1] = '\0';
        offset += INPUT_NAME_SIZE_MAX;
        datas.WriteCString(networkId);
    }
    GearMode mode;
    memset_s(&mode, sizeof(GearMode), 0, sizeof(GearMode));
    if (memcpy_s(&mode, sizeof(GearMode), reinterpret_cast<const GearMode *>(data + offset),
        sizeof(GearMode)) != EOK) {
        return;
    }
    datas.WriteRawData(&mode, sizeof(GearMode));
}

bool ShiftLNNGearFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(bool) + INPUT_NAME_SIZE_MAX * SIZE_NUM_THREE
        + sizeof(GearMode) || size >= INT32_MAX - 1) {
        return false;
    }
    MessageParcel datas;
    ShiftLNNGearInfoProc(data, datas);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->ShiftLNNGearInner(datas, reply);
    return true;
}

bool RippleStatsFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < sizeof(int32_t) + sizeof(int32_t) + sizeof(TrafficStats) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    int32_t channelId = *reinterpret_cast<const int32_t *>(data);
    offset = sizeof(int32_t);
    int32_t channelType = *reinterpret_cast<const int32_t *>(data + offset);
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

bool SoftbusRegisterServiceFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < INPUT_NAME_SIZE_MAX + sizeof(IRemoteObject) ||
        size >= INT32_MAX - 1) {
        return false;
    }
    uint32_t offset = 0;
    sptr<IRemoteObject> obj;
    memset_s(obj, sizeof(IRemoteObject), 0, sizeof(IRemoteObject));
    if (memcpy_s(obj, sizeof(IRemoteObject), reinterpret_cast<const IRemoteObject *>(data),
        sizeof(IRemoteObject)) != EOK) {
        return false;
    }
    offset += sizeof(IRemoteObject);
    char pkgName[INPUT_NAME_SIZE_MAX] = "";
    if (memcpy_s(pkgName, INPUT_NAME_SIZE_MAX, reinterpret_cast<const char *>(data + offset),
        INPUT_NAME_SIZE_MAX - 1) != EOK) {
        return false;
    }
    pkgName[INPUT_NAME_SIZE_MAX - 1] = '\0';
    offset += INPUT_NAME_SIZE_MAX;
    MessageParcel datas;
    datas.WriteRemoteObject(obj);
    datas.WriteCString(pkgName);
    MessageParcel reply;
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return false;
    }
    SoftBusServer->SoftbusRegisterServiceInner(datas, reply);
    return true;
}

bool CheckOpenSessionPermissionFuzzTest(const uint8_t *data, size_t size)
{
#define SESSION_NAME_SIZE_MAX 256
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || data == nullptr || size < DEVICE_ID_SIZE_MAX + GROUP_ID_SIZE_MAX ||
        size >= INT32_MAX - 1) {
        return false;
    }
    SetAccessTokenPermission("SoftBusServerStubTest");
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

bool EvaLuateQosInnerFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || size == 0 || size >= INT32_MAX - 1) {
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
    SetAccessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_EVALUATE_QOS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool EvaLuateQosInnerNetworkIdFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || size == 0 || size >= INT32_MAX - 1) {
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
    SetAccessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_EVALUATE_QOS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool EvaLuateQosInnerDataTypeFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || size == 0 || size >= INT32_MAX - 1) {
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
    SetAccessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_EVALUATE_QOS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool EvaLuateQosInnerQosCountFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> object = GetRemoteObject();
    if (object == nullptr || size == 0 || size >= INT32_MAX - 1) {
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
    SetAccessTokenPermission("SoftBusServerStubTest");
    if (object->SendRequest(SERVER_EVALUATE_QOS, datas, reply, option) != ERR_NONE) {
        return false;
    }
    return true;
}

bool RunFuzzTestCase(const uint8_t *data, size_t size)
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
    OHOS::SoftbusRegisterServiceFuzzTest(data, size);
    OHOS::CheckOpenSessionPermissionFuzzTest(data, size);
    OHOS::EvaLuateQosInnerFuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* ptr, size_t size)
{
    if (ptr == nullptr) {
        return 0;
    }
    OHOS::RunFuzzTestCase(ptr, size);
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(size + 1));
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
