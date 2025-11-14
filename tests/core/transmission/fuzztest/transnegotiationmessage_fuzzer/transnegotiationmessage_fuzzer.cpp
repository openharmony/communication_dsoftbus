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

#include "transnegotiationmessage_fuzzer.h"

#include "fuzz_data_generator.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"
#include "softbus_message_open_channel.h"
#include "softbus_proxychannel_message.h"
#include "trans_auth_message.h"
#include "trans_udp_negotiation_exchange.h"

namespace OHOS {
constexpr uint32_t TRANS_FUZZ_TEST_BASE = 100;
std::string TRANS_FUZZ_STR_VAL;
int32_t TRANS_FUZZ_INT_VAL = 0;
int64_t TRANS_FUZZ_INT64_VAL = 0;
int16_t TRANS_FUZZ_INT16_VAL = 0;

/*
 * The testing of the protocol content is divided into several parts:
 * 1. Constructing scenarios with missing fields;
 * 2. Constructing scenarios with random field contents;
*/
// Discard specific field messages in sequence
static bool CheckAddItem(uint32_t index, bool newCase)
{
    static uint32_t base = 0;
    if (newCase) {
        base = 0;
    }

    bool ret = true;
    if (index == base) {
        ret = false;
    }

    base++;

    return ret;
}

static void ProxyChannelAckAddItem(uint32_t index, cJSON *root)
{
    if (CheckAddItem(index, false)) {
        int32_t pid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_PID, pid);
    }

    if (CheckAddItem(index, false)) {
        const char *pkgName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_PKG_NAME, pkgName);
    }

    if (CheckAddItem(index, false)) {
        int32_t encrypt = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_ENCRYPT, encrypt);
    }

    if (CheckAddItem(index, false)) {
        int32_t algorithm = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_ALGORITHM, algorithm);
    }

    if (CheckAddItem(index, false)) {
        int32_t crc = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_CRC, crc);
    }

    if (CheckAddItem(index, false)) {
        int32_t fastTransDataSize = TRANS_FUZZ_INT_VAL;
        (void)AddNumber16ToJsonObject(root, JSON_KEY_FIRST_DATA_SIZE, fastTransDataSize);
    }

    if (CheckAddItem(index, false)) {
        const char *localSessionName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_SRC_BUS_NAME, localSessionName);
    }

    if (CheckAddItem(index, false)) {
        const char *PeerSessionName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_DST_BUS_NAME, PeerSessionName);
    }

    if (CheckAddItem(index, false)) {
        int32_t myHandleId = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_MY_HANDLE_ID, myHandleId);
    }
}

static bool ProxyChannelNegMessageAckFuzzTest(uint32_t index)
{
    ProxyChannelInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return false;
    }

    if (CheckAddItem(index, true)) {
        const char *identity = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_IDENTITY, identity);
    }

    if (CheckAddItem(index, false)) {
        const char *deviceId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_DEVICE_ID, deviceId);
    }

    if (CheckAddItem(index, false)) {
        int32_t channelCapability = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, TRANS_CAPABILITY, channelCapability);
    }

    if (CheckAddItem(index, false)) {
        int32_t dataConfig = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_MTU_SIZE, dataConfig);
    }

    if (CheckAddItem(index, false)) {
        (void)cJSON_AddTrueToObject(root, JSON_KEY_HAS_PRIORITY);
    }

    if (CheckAddItem(index, false)) {
        int32_t uid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_UID, uid);
    }

    ProxyChannelAckAddItem(index, root);

    char *msg = cJSON_PrintUnformatted(root);
    if (msg == nullptr) {
        cJSON_Delete(root);
        return false;
    }

    uint16_t fastDataSize = 0;
    (void)TransProxyUnpackHandshakeAckMsg(msg, &info, strlen(msg), &fastDataSize);

    cJSON_free(msg);
    cJSON_Delete(root);

    return true;
}

static void ProxyAddItemToJson(uint32_t index, cJSON *root)
{
    if (CheckAddItem(index, false)) {
        int32_t appType = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_TYPE, appType);
    }

    if (CheckAddItem(index, false)) {
        const char *identity = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_IDENTITY, identity);
    }

    if (CheckAddItem(index, false)) {
        const char *localSessionName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_SRC_BUS_NAME, localSessionName);
    }

    if (CheckAddItem(index, false)) {
        const char *PeerSessionName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_DST_BUS_NAME, PeerSessionName);
    }

    if (CheckAddItem(index, false)) {
        const char *deviceId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_DEVICE_ID, deviceId);
    }

    if (CheckAddItem(index, false)) {
        int32_t apiVersion = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, API_VERSION, apiVersion);
    }

    if (CheckAddItem(index, false)) {
        int32_t channelCapability = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, TRANS_CAPABILITY, channelCapability);
    }

    if (CheckAddItem(index, false)) {
        int32_t dataConfig = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_MTU_SIZE, dataConfig);
    }

    if (CheckAddItem(index, false)) {
        int32_t uid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_UID, uid);
    }

    if (CheckAddItem(index, false)) {
        int32_t pid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_PID, pid);
    }

    if (CheckAddItem(index, false)) {
        const char *groupId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_GROUP_ID, groupId);
    }

    if (CheckAddItem(index, false)) {
        const char *pkgName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_PKG_NAME, pkgName);
    }
}

static void ProxyReqAddItemToJson(uint32_t index, cJSON *root)
{
    if (CheckAddItem(index, false)) {
        const char *sessionKeyBase64 = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_SESSION_KEY, sessionKeyBase64);
    }

    if (CheckAddItem(index, false)) {
        int32_t encrypt = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_ENCRYPT, encrypt);
    }

    if (CheckAddItem(index, false)) {
        int32_t algorithm = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_ALGORITHM, algorithm);
    }

    if (CheckAddItem(index, false)) {
        int32_t crc = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_CRC, crc);
    }

    if (CheckAddItem(index, false)) {
        int16_t fastTransDataSize = TRANS_FUZZ_INT16_VAL;
        (void)AddNumber16ToJsonObject(root, JSON_KEY_FIRST_DATA_SIZE, fastTransDataSize);
    }

    if (CheckAddItem(index, false)) {
        int32_t encodeFastData = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_FIRST_DATA, encodeFastData);
    }

    if (CheckAddItem(index, false)) {
        int32_t myHandleId = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_MY_HANDLE_ID, myHandleId);
    }

    if (CheckAddItem(index, false)) {
        int32_t userId = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_USER_ID, userId);
    }

    if (CheckAddItem(index, false)) {
        const char *accountId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(root, JSON_KEY_ACCOUNT_ID, accountId);
    }
}

static bool ProxyChannelNegMessageReqFuzzTest(uint32_t index)
{
    ProxyChannelInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return false;
    }

    if (CheckAddItem(index, true)) {
        (void)cJSON_AddTrueToObject(root, JSON_KEY_HAS_PRIORITY);
    }

    ProxyAddItemToJson(index, root);

    ProxyReqAddItemToJson(index, root);

    if (CheckAddItem(index, false)) {
        int32_t businessType = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_BUSINESS_TYPE, businessType);
    }

    if (CheckAddItem(index, false)) {
        int32_t chanFlag = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_TRANS_FLAGS, chanFlag);
    }

    if (CheckAddItem(index, false)) {
        int32_t peerHandleId = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(root, JSON_KEY_PEER_HANDLE_ID, peerHandleId);
    }

    if (CheckAddItem(index, false)) {
        int64_t callingTokenId = TRANS_FUZZ_INT64_VAL;
        (void)AddNumber64ToJsonObject(root, JSON_KEY_CALLING_TOKEN_ID, callingTokenId);
    }

    char *msg = cJSON_PrintUnformatted(root);
    if (msg == nullptr) {
        cJSON_Delete(root);
        return false;
    }

    (void)TransProxyUnpackHandshakeMsg(msg, &info, strlen(msg));

    cJSON_free(msg);
    cJSON_Delete(root);

    return true;
}

static bool ProxyChannelNegMessageIdentityFuzzTest()
{
    char identity[IDENTITY_LEN + 1] = { 0 };

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return false;
    }

    const char *str = TRANS_FUZZ_STR_VAL.c_str();
    (void)AddStringToJsonObject(root, JSON_KEY_IDENTITY, str);

    char *msg = cJSON_PrintUnformatted(root);
    if (msg == nullptr) {
        cJSON_Delete(root);
        return false;
    }

    (void)TransProxyUnpackIdentity(msg, identity, sizeof(identity), strlen(msg));

    cJSON_free(msg);
    cJSON_Delete(root);

    return true;
}

static bool ProxyChannelNegMessageErrorFuzzTest()
{
    int32_t errCode;

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return false;
    }

    int32_t value = TRANS_FUZZ_INT_VAL;
    (void)AddNumberToJsonObject(root, ERR_CODE, value);

    char *msg = cJSON_PrintUnformatted(root);
    if (msg == nullptr) {
        cJSON_Delete(root);
        return false;
    }

    (void)TransProxyUnPackHandshakeErrMsg(msg, &errCode, strlen(msg));

    cJSON_free(msg);
    cJSON_Delete(root);

    return true;
}

static bool ProxyChannelNegMessageResetErrorFuzzTest()
{
    int32_t resetCode = 0;

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return false;
    }

    int32_t value = TRANS_FUZZ_INT_VAL;
    (void)AddNumberToJsonObject(root, ERR_CODE, value);
    (void)AddNumberToJsonObject(root, "ERROR_CODE", value);

    char *msg = cJSON_PrintUnformatted(root);
    if (msg == nullptr) {
        cJSON_Delete(root);
        return false;
    }

    (void)TransProxyUnPackRestErrMsg(msg, &resetCode, strlen(msg));

    cJSON_free(msg);
    cJSON_Delete(root);

    return true;
}

static void ProxyChannelAbnormalErrMsg()
{
    int32_t errCode = 0;

    const char *msg = TRANS_FUZZ_STR_VAL.c_str();
    (void)TransProxyUnPackHandshakeErrMsg(msg, &errCode, strlen(msg));
}

static void ProxyChannelAbnormalRestErr()
{
    int32_t resetCode = 0;

    const char *msg = TRANS_FUZZ_STR_VAL.c_str();
    (void)TransProxyUnPackRestErrMsg(msg, &resetCode, strlen(msg));
}

static void ProxyChannelAbnormalAckMsg()
{
    ProxyChannelInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    uint16_t fastDataSize = 0;
    const char *msg = TRANS_FUZZ_STR_VAL.c_str();
    (void)TransProxyUnpackHandshakeAckMsg(msg, &info, strlen(msg), &fastDataSize);
}

static void ProxyChannelAbnormalHandshake()
{
    ProxyChannelInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    const char *msg = TRANS_FUZZ_STR_VAL.c_str();
    (void)TransProxyUnpackHandshakeMsg(msg, &info, strlen(msg));
}

static void ProxyChannelAbnormalIdentity()
{
    char identity[IDENTITY_LEN + 1] = { 0 };

    const char *msg = TRANS_FUZZ_STR_VAL.c_str();
    (void)TransProxyUnpackIdentity(msg, identity, sizeof(identity), strlen(msg));
}

static void ProxyChannelAbnormalTest()
{
    ProxyChannelAbnormalErrMsg();
    ProxyChannelAbnormalRestErr();
    ProxyChannelAbnormalAckMsg();
    ProxyChannelAbnormalHandshake();
    ProxyChannelAbnormalIdentity();
}

static bool ProxyChannelNegMessageFuzzTest()
{
    static uint32_t index = 0;
    if (index > TRANS_FUZZ_TEST_BASE) {
        index = 0;
    }

    (void)ProxyChannelNegMessageAckFuzzTest(index);
    (void)ProxyChannelNegMessageReqFuzzTest(index);
    (void)ProxyChannelNegMessageIdentityFuzzTest();
    (void)ProxyChannelNegMessageResetErrorFuzzTest();
    (void)ProxyChannelNegMessageErrorFuzzTest();
    (void)ProxyChannelAbnormalTest();

    index++;

    return true;
}

static bool UdpChannelNegMessageErrorFuzzTest()
{
    int32_t resetCode;

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return false;
    }

    int32_t value = TRANS_FUZZ_INT_VAL;
    (void)AddNumberToJsonObject(root, ERR_CODE, value);

    (void)TransUnpackReplyErrInfo(root, &resetCode);
    cJSON_Delete(root);

    return true;
}

static void UdpChannelReplyAddItem(uint32_t index, cJSON *msg)
{
    if (CheckAddItem(index, false)) {
        const char *pkgName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "PKG_NAME", pkgName);
    }

    if (CheckAddItem(index, false)) {
        int32_t uid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "UID", uid);
    }

    if (CheckAddItem(index, false)) {
        int32_t pid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "PID", pid);
    }

    if (CheckAddItem(index, false)) {
        int32_t businessType = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "BUSINESS_TYPE", businessType);
    }

    if (CheckAddItem(index, false)) {
        int32_t streamType = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "STREAM_TYPE", streamType);
    }

    if (CheckAddItem(index, false)) {
        int32_t apiVersion = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "API_VERSION", apiVersion);
    }

    if (CheckAddItem(index, false)) {
        int32_t channelCapability = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "TRANS_CAPABILITY", channelCapability);
    }

    if (CheckAddItem(index, false)) {
        int32_t udpChannelCapability = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "UDP_CHANNEL_CAPABILITY", udpChannelCapability);
    }
}

static bool UdpChannelNegMessageReplyFuzzTest(uint32_t index)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(appInfo), 0, sizeof(appInfo));

    cJSON *msg = cJSON_CreateObject();
    if (msg == nullptr) {
        return false;
    }

    if (CheckAddItem(index, true)) {
        int64_t channelId = TRANS_FUZZ_INT64_VAL;
        (void)AddNumber64ToJsonObject(msg, "MY_CHANNEL_ID", channelId);
    }

    if (CheckAddItem(index, false)) {
        int32_t port = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "MY_PORT", port);
    }

    if (CheckAddItem(index, false)) {
        const char *addr = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "MY_IP", addr);
    }

    if (CheckAddItem(index, false)) {
        int32_t type = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "CODE", type);
    }

    UdpChannelReplyAddItem(index, msg);

    (void)TransUnpackReplyUdpInfo(msg, &appInfo);
    cJSON_Delete(msg);

    return true;
}

static bool UdpChannelAbnormalReply()
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(appInfo), 0, sizeof(appInfo));

    cJSON *msg = cJSON_CreateObject();
    if (msg == nullptr) {
        return false;
    }

    (void)TransUnpackReplyUdpInfo(msg, &appInfo);
    cJSON_Delete(msg);

    (void)TransUnpackReplyUdpInfo(nullptr, &appInfo);
    (void)TransUnpackReplyUdpInfo(nullptr, nullptr);

    return true;
}

static bool UdpChannelAbnormalError()
{
    int32_t resetCode;

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return false;
    }

    (void)TransUnpackReplyErrInfo(root, &resetCode);
    cJSON_Delete(root);

    (void)TransUnpackReplyErrInfo(nullptr, &resetCode);
    (void)TransUnpackReplyErrInfo(nullptr, nullptr);

    return true;
}

static void UdpChannelAbnormalTest()
{
    (void)UdpChannelAbnormalReply();
    (void)UdpChannelAbnormalError();
}

static bool UdpChannelNegMessageFuzzTest()
{
    static uint32_t index = 0;
    if (index > TRANS_FUZZ_TEST_BASE) {
        index = 0;
    }

    (void)UdpChannelNegMessageErrorFuzzTest();
    (void)UdpChannelNegMessageReplyFuzzTest(index);
    UdpChannelAbnormalTest();

    index++;

    return true;
}

static void DirectChannelReplyAddItem(uint32_t index, cJSON *msg)
{
    if (CheckAddItem(index, false)) {
        int32_t dataConfig = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, MTU_SIZE, dataConfig);
    }

    if (CheckAddItem(index, false)) {
        int32_t fastTransDataSize = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, FIRST_DATA_SIZE, fastTransDataSize);
    }

    if (CheckAddItem(index, false)) {
        const char *pkgName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, PKG_NAME, pkgName);
    }

    if (CheckAddItem(index, false)) {
        const char *authState = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, AUTH_STATE, authState);
    }

    if (CheckAddItem(index, false)) {
        int32_t myHandleId = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, MY_HANDLE_ID, myHandleId);
    }

    if (CheckAddItem(index, false)) {
        int32_t peerHandleId = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, PEER_HANDLE_ID, peerHandleId);
    }
}

static bool DirectChannelNegMessageReplyFuzzTest(uint32_t index)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(appInfo), 0, sizeof(appInfo));

    cJSON *msg = cJSON_CreateObject();
    if (msg == nullptr) {
        return false;
    }

    if (CheckAddItem(index, true)) {
        int32_t channel = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, CODE, channel);
    }

    if (CheckAddItem(index, false)) {
        int32_t apiVersion = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, API_VERSION, apiVersion);
    }

    if (CheckAddItem(index, false)) {
        const char *deviceId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, DEVICE_ID, deviceId);
    }

    if (CheckAddItem(index, false)) {
        int32_t uid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, UID, uid);
    }

    if (CheckAddItem(index, false)) {
        int32_t pid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, PID, pid);
    }

    if (CheckAddItem(index, false)) {
        int32_t channelCapability = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, TRANS_CAPABILITY, channelCapability);
    }

    DirectChannelReplyAddItem(index, msg);

    uint16_t fastDataSize = 0;
    (void)UnpackReply(msg, &appInfo, &fastDataSize);
    cJSON_Delete(msg);

    return true;
}

static void DirectChannelAddItemToJson(uint32_t index, cJSON *msg)
{
    if (CheckAddItem(index, false)) {
        int32_t fastTransDataSize = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, FIRST_DATA_SIZE, fastTransDataSize);
    }

    if (CheckAddItem(index, false)) {
        const char *encodeFastData = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, FIRST_DATA, encodeFastData);
    }

    if (CheckAddItem(index, false)) {
        int32_t channel = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, CODE, channel);
    }

    if (CheckAddItem(index, false)) {
        int32_t apiVersion = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, API_VERSION, apiVersion);
    }

    if (CheckAddItem(index, false)) {
        const char *peerSessionName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, BUS_NAME, peerSessionName);
    }

    if (CheckAddItem(index, false)) {
        const char *groupId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, GROUP_ID, groupId);
    }

    if (CheckAddItem(index, false)) {
        int32_t uid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, UID, uid);
    }

    if (CheckAddItem(index, false)) {
        int32_t pid = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, PID, pid);
    }

    if (CheckAddItem(index, false)) {
        const char *encodeSessionKey = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, SESSION_KEY, encodeSessionKey);
    }

    if (CheckAddItem(index, false)) {
        int32_t dataConfig = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, MTU_SIZE, dataConfig);
    }

    if (CheckAddItem(index, false)) {
        int32_t channelCapability = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, TRANS_CAPABILITY, channelCapability);
    }

    if (CheckAddItem(index, false)) {
        const char *accountId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, ACCOUNT_ID, accountId);
    }
}

static void DirectChannelAddItemToJson2(uint32_t index, cJSON *msg)
{
    if (CheckAddItem(index, false)) {
        const char *authState = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, AUTH_STATE, authState);
    }

    if (CheckAddItem(index, false)) {
        int32_t routeType = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, MSG_ROUTE_TYPE, routeType);
    }

    if (CheckAddItem(index, false)) {
        int32_t businessType = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, BUSINESS_TYPE, businessType);
    }

    if (CheckAddItem(index, false)) {
        int32_t autoCloseTime = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, AUTO_CLOSE_TIME, autoCloseTime);
    }

    if (CheckAddItem(index, false)) {
        int32_t transFlag = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, TRANS_FLAGS, transFlag);
    }

    if (CheckAddItem(index, false)) {
        int32_t myHandleId = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, MY_HANDLE_ID, myHandleId);
    }

    if (CheckAddItem(index, false)) {
        int32_t peerHandleId = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, PEER_HANDLE_ID, peerHandleId);
    }

    if (CheckAddItem(index, false)) {
        int64_t callingTokenId = TRANS_FUZZ_INT64_VAL;
        (void)AddNumber64ToJsonObject(msg, JSON_KEY_CALLING_TOKEN_ID, callingTokenId);
    }

    if (CheckAddItem(index, false)) {
        int32_t userId = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, USER_ID, userId);
    }
}

static bool DirectChannelNegMessageRequestFuzzTest(uint32_t index)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(appInfo), 0, sizeof(appInfo));

    cJSON *msg = cJSON_CreateObject();
    if (msg == nullptr) {
        return false;
    }

    if (CheckAddItem(index, true)) {
        const char *pkgName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, PKG_NAME, pkgName);
    }

    if (CheckAddItem(index, false)) {
        const char *localSessionName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, CLIENT_BUS_NAME, localSessionName);
    }

    DirectChannelAddItemToJson(index, msg);

    DirectChannelAddItemToJson2(index, msg);

    (void)UnpackRequest(msg, &appInfo);
    cJSON_Delete(msg);

    return true;
}

static bool DirectChannelAbnormalReply()
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(appInfo), 0, sizeof(appInfo));

    cJSON *msg = cJSON_CreateObject();
    if (msg == nullptr) {
        return false;
    }

    uint16_t fastDataSize = 0;
    (void)UnpackReply(msg, &appInfo, &fastDataSize);
    cJSON_Delete(msg);

    (void)UnpackReply(nullptr, &appInfo, &fastDataSize);
    (void)UnpackReply(nullptr, nullptr, &fastDataSize);

    return true;
}

static bool DirectChannelAbnormalRequest()
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(appInfo), 0, sizeof(appInfo));

    cJSON *msg = cJSON_CreateObject();
    if (msg == nullptr) {
        return false;
    }

    (void)UnpackRequest(msg, &appInfo);
    cJSON_Delete(msg);

    (void)UnpackRequest(nullptr, &appInfo);
    (void)UnpackRequest(nullptr, nullptr);

    return true;
}

static void DirectChannelAbnormalTest()
{
    (void)DirectChannelAbnormalReply();
    (void)DirectChannelAbnormalRequest();
}

static bool DirectChannelNegMessageFuzzTest()
{
    static uint32_t index = 0;
    if (index > TRANS_FUZZ_TEST_BASE) {
        index = 0;
    }

    (void)DirectChannelNegMessageReplyFuzzTest(index);
    (void)DirectChannelNegMessageRequestFuzzTest(index);
    DirectChannelAbnormalTest();

    index++;

    return true;
}

static void AuthChannelAddItem(uint32_t index, cJSON *msg)
{
    if (CheckAddItem(index, false)) {
        const char *PeerSessionName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "DST_BUS_NAME", PeerSessionName);
    }

    if (CheckAddItem(index, false)) {
        const char *reqId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "REQ_ID", reqId);
    }

    if (CheckAddItem(index, false)) {
        int32_t dataConfig = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "MTU_SIZE", dataConfig);
    }

    if (CheckAddItem(index, false)) {
        int32_t apiVersion = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "API_VERSION", apiVersion);
    }

    if (CheckAddItem(index, false)) {
        int32_t routeType = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "ROUTE_TYPE", routeType);
    }

    if (CheckAddItem(index, false)) {
        int32_t linkType = TRANS_FUZZ_INT_VAL;
        (void)AddNumberToJsonObject(msg, "LANE_LINK_TYPE", linkType);
    }

    if (CheckAddItem(index, false)) {
        const char *localAddr = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "LOCAL_HML_RAW_IP", localAddr);
    }

    if (CheckAddItem(index, false)) {
        const char *peerAddr = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "PEER_HML_RAW_IP", peerAddr);
    }
}

static bool AuthChannelNegMessageNormalFuzzTest(uint32_t index)
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == nullptr) {
        return false;
    }

    if (CheckAddItem(index, true)) {
        int32_t channel = TRANS_FUZZ_INT_VAL;
        AddNumberToJsonObject(msg, "CODE", channel);
    }

    if (CheckAddItem(index, false)) {
        const char *deviceId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "DEVICE_ID", deviceId);
    }

    if (CheckAddItem(index, false)) {
        const char *peerNetWorkId = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "PEER_NETWORK_ID", peerNetWorkId);
    }

    if (CheckAddItem(index, false)) {
        const char *pkgName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "PKG_NAME", pkgName);
    }

    if (CheckAddItem(index, false)) {
        const char *localSessionName = TRANS_FUZZ_STR_VAL.c_str();
        (void)AddStringToJsonObject(msg, "SRC_BUS_NAME", localSessionName);
    }

    AuthChannelAddItem(index, msg);

    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(appInfo), 0, sizeof(appInfo));

    char *dataBuf = cJSON_PrintUnformatted(msg);
    if (dataBuf == nullptr) {
        cJSON_Delete(msg);
        return false;
    }

    (void)TransAuthChannelMsgUnpack(dataBuf, &appInfo, strlen(dataBuf));

    cJSON_free(dataBuf);
    cJSON_Delete(msg);
    return true;
}

static bool AuthChannelNegMessageErrorFuzzTest()
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == nullptr) {
        return false;
    }

    int32_t err = TRANS_FUZZ_INT_VAL;
    AddNumberToJsonObject(msg, "ERR_CODE", err);

    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(appInfo), 0, sizeof(appInfo));

    char *dataBuf = cJSON_PrintUnformatted(msg);
    if (dataBuf == nullptr) {
        cJSON_Delete(msg);
        return false;
    }

    (void)TransAuthChannelMsgUnpack(dataBuf, &appInfo, strlen(dataBuf));

    (void)TransAuthChannelMsgUnpack(nullptr, &appInfo, 0);
    (void)TransAuthChannelMsgUnpack(dataBuf, nullptr, strlen(dataBuf));
    (void)TransAuthChannelMsgUnpack(nullptr, nullptr, strlen(dataBuf));
    (void)TransAuthChannelMsgUnpack(nullptr, nullptr, 0);

    cJSON_free(dataBuf);
    cJSON_Delete(msg);
    return true;
}

static bool AuthChannelNegMessageFuzzTest()
{
    static uint32_t index = 0;
    if (index > TRANS_FUZZ_TEST_BASE) {
        index = 0;
    }

    (void)AuthChannelNegMessageNormalFuzzTest(index);
    (void)AuthChannelNegMessageErrorFuzzTest();

    index++;

    return true;
}

bool RunFuzzTestCaseWithStr(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return false;
    }

    DataGenerator::Write(data, size);
    GenerateInt32(TRANS_FUZZ_INT_VAL);
    GenerateInt64(TRANS_FUZZ_INT64_VAL);
    GenerateInt16(TRANS_FUZZ_INT16_VAL);
    GenerateString(TRANS_FUZZ_STR_VAL);
    DataGenerator::Clear();

    (void)ProxyChannelNegMessageFuzzTest();
    (void)UdpChannelNegMessageFuzzTest();
    (void)DirectChannelNegMessageFuzzTest();
    (void)AuthChannelNegMessageFuzzTest();

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *ptr, size_t size)
{
    if (ptr == nullptr) {
        return 0;
    }

    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(size + 1));
    if (data == nullptr) {
        return 0;
    }

    if (memcpy_s(data, size, ptr, size) != EOK) {
        SoftBusFree(data);
        return 0;
    }

    OHOS::RunFuzzTestCaseWithStr(data, size);
    SoftBusFree(data);

    return 0;
}
