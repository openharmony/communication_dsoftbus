/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "trans_udp_negotiation_exchange.h"

#include "regex.h"
#include "softbus_message_open_channel.h"
#include "softbus_adapter_crypto.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "trans_log.h"

#define BASE64_SESSION_KEY_LEN 45
typedef enum {
    CODE_EXCHANGE_UDP_INFO = 6,
    CODE_FILE_TRANS_UDP = 0x602
} CodeType;

#define ISHARE_SESSION_NAME "IShare*"

static inline bool IsIShareSession(const char* sessionName)
{
    regex_t regComp;
    if (regcomp(&regComp, ISHARE_SESSION_NAME, REG_EXTENDED | REG_NOSUB) != 0) {
        TRANS_LOGE(TRANS_CTRL, "regcomp failed.");
        return false;
    }
    bool compare = regexec(&regComp, sessionName, 0, NULL, 0) == 0;
    regfree(&regComp);
    return compare;
}

static inline CodeType getCodeType(const AppInfo *appInfo)
{
    return ((appInfo->udpConnType == UDP_CONN_TYPE_P2P) &&
        IsIShareSession(appInfo->myData.sessionName) && (IsIShareSession(appInfo->peerData.sessionName))) ?
        CODE_FILE_TRANS_UDP : CODE_EXCHANGE_UDP_INFO;
}

int32_t TransUnpackReplyErrInfo(const cJSON *msg, int32_t *errCode)
{
    if ((msg == NULL) && (errCode == NULL)) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectInt32Item(msg, ERR_CODE, errCode)) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransUnpackReplyUdpInfo(const cJSON *msg, AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "unpack reply udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_ERR;
    }

    (void)GetJsonObjectStringItem(msg, "PKG_NAME", appInfo->peerData.pkgName, PKG_NAME_SIZE_MAX);
    (void)GetJsonObjectNumberItem(msg, "UID", &(appInfo->peerData.uid));
    (void)GetJsonObjectNumberItem(msg, "PID", &(appInfo->peerData.pid));
    (void)GetJsonObjectNumberItem(msg, "BUSINESS_TYPE", (int*)&(appInfo->businessType));

    int code = CODE_EXCHANGE_UDP_INFO;
    (void)GetJsonObjectNumberItem(msg, "CODE", &code);
    if ((code == CODE_FILE_TRANS_UDP) && (getCodeType(appInfo) == CODE_FILE_TRANS_UDP)) {
        appInfo->fileProtocol = APP_INFO_UDP_FILE_PROTOCOL;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)GetJsonObjectNumber64Item(msg, "MY_CHANNEL_ID", &(appInfo->peerData.channelId));
            (void)GetJsonObjectNumberItem(msg, "MY_PORT", &(appInfo->peerData.port));
            (void)GetJsonObjectStringItem(msg, "MY_IP", appInfo->peerData.addr, sizeof(appInfo->peerData.addr));
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransUnpackRequestUdpInfo(const cJSON *msg, AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "unpack request udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_ERR;
    }
    unsigned char encodeSessionKey[BASE64_SESSION_KEY_LEN] = {0};
    size_t len = 0;
    (void)GetJsonObjectStringItem(msg, "SESSION_KEY", (char*)encodeSessionKey, BASE64_SESSION_KEY_LEN);
    int32_t ret = SoftBusBase64Decode((unsigned char*)appInfo->sessionKey, sizeof(appInfo->sessionKey), &len,
        (unsigned char*)encodeSessionKey, strlen((char*)encodeSessionKey));
    if (len != sizeof(appInfo->sessionKey) || ret != 0) {
        TRANS_LOGE(TRANS_CTRL, "mbedtls decode failed.");
        return SOFTBUS_ERR;
    }

    (void)GetJsonObjectStringItem(msg, "PKG_NAME", appInfo->peerData.pkgName, PKG_NAME_SIZE_MAX);
    (void)GetJsonObjectStringItem(msg, "BUS_NAME", appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX);
    (void)GetJsonObjectStringItem(msg, "CLIENT_BUS_NAME", appInfo->peerData.sessionName, SESSION_NAME_SIZE_MAX);
    (void)GetJsonObjectStringItem(msg, "GROUP_ID", appInfo->groupId, GROUP_ID_SIZE_MAX);

    (void)GetJsonObjectNumberItem(msg, "API_VERSION", (int*)&(appInfo->peerData.apiVersion));
    (void)GetJsonObjectNumberItem(msg, "PID", &(appInfo->peerData.pid));
    (void)GetJsonObjectNumberItem(msg, "UID", &(appInfo->peerData.uid));
    (void)GetJsonObjectNumberItem(msg, "BUSINESS_TYPE", (int*)&(appInfo->businessType));
    (void)GetJsonObjectNumberItem(msg, "STREAM_TYPE", (int*)&(appInfo->streamType));
    (void)GetJsonObjectNumberItem(msg, "CHANNEL_TYPE", (int *)&(appInfo->udpChannelOptType));
    (void)GetJsonObjectNumberItem(msg, "UDP_CONN_TYPE", (int *)&(appInfo->udpConnType));

    int code = CODE_EXCHANGE_UDP_INFO;
    (void)GetJsonObjectNumberItem(msg, "CODE", &code);
    if ((code == CODE_FILE_TRANS_UDP) && (getCodeType(appInfo) == CODE_FILE_TRANS_UDP)) {
        appInfo->fileProtocol = APP_INFO_UDP_FILE_PROTOCOL;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)GetJsonObjectNumber64Item(msg, "MY_CHANNEL_ID", &(appInfo->peerData.channelId));
            (void)GetJsonObjectStringItem(msg, "MY_IP", appInfo->peerData.addr, sizeof(appInfo->peerData.addr));
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            (void)GetJsonObjectNumber64Item(msg, "PEER_CHANNEL_ID", &(appInfo->myData.channelId));
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransPackRequestUdpInfo(cJSON *msg, const AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "pack request udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_ERR;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)AddNumber64ToJsonObject(msg, "MY_CHANNEL_ID", appInfo->myData.channelId);
            (void)AddStringToJsonObject(msg, "MY_IP", appInfo->myData.addr);
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            (void)AddNumber64ToJsonObject(msg, "PEER_CHANNEL_ID", appInfo->peerData.channelId);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_ERR;
    }
    char encodeSessionKey[BASE64_SESSION_KEY_LEN] = {0};
    size_t len = 0;
    int32_t ret = SoftBusBase64Encode((unsigned char*)encodeSessionKey, BASE64_SESSION_KEY_LEN, &len,
        (unsigned char*)appInfo->sessionKey, sizeof(appInfo->sessionKey));
    if (ret != 0) {
        TRANS_LOGE(TRANS_CTRL, "mbedtls base64 encode failed.");
        return SOFTBUS_ERR;
    }
    (void)AddStringToJsonObject(msg, "SESSION_KEY", encodeSessionKey);

    (void)AddNumberToJsonObject(msg, "CODE", getCodeType(appInfo));
    (void)AddNumberToJsonObject(msg, "API_VERSION", appInfo->myData.apiVersion);
    (void)AddNumberToJsonObject(msg, "UID", appInfo->myData.uid);
    (void)AddNumberToJsonObject(msg, "PID", appInfo->myData.pid);
    (void)AddNumberToJsonObject(msg, "BUSINESS_TYPE", appInfo->businessType);
    (void)AddNumberToJsonObject(msg, "STREAM_TYPE", appInfo->streamType);
    (void)AddNumberToJsonObject(msg, "CHANNEL_TYPE", appInfo->udpChannelOptType);
    (void)AddNumberToJsonObject(msg, "UDP_CONN_TYPE", appInfo->udpConnType);

    (void)AddStringToJsonObject(msg, "BUS_NAME", appInfo->peerData.sessionName);
    (void)AddStringToJsonObject(msg, "CLIENT_BUS_NAME", appInfo->myData.sessionName);
    (void)AddStringToJsonObject(msg, "GROUP_ID", appInfo->groupId);
    (void)AddStringToJsonObject(msg, "PKG_NAME", appInfo->myData.pkgName);

    return SOFTBUS_OK;
}

int32_t TransPackReplyUdpInfo(cJSON *msg, const AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "pack reply udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_ERR;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)AddNumber64ToJsonObject(msg, "MY_CHANNEL_ID", appInfo->myData.channelId);
            (void)AddNumberToJsonObject(msg, "MY_PORT", appInfo->myData.port);
            (void)AddStringToJsonObject(msg, "MY_IP", appInfo->myData.addr);
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_ERR;
    }

    (void)AddNumberToJsonObject(msg, "CODE", getCodeType(appInfo));
    (void)AddStringToJsonObject(msg, "PKG_NAME", appInfo->myData.pkgName);
    (void)AddNumberToJsonObject(msg, "UID", appInfo->myData.uid);
    (void)AddNumberToJsonObject(msg, "PID", appInfo->myData.pid);
    (void)AddNumberToJsonObject(msg, "BUSINESS_TYPE", appInfo->businessType);
    (void)AddNumberToJsonObject(msg, "STREAM_TYPE", appInfo->streamType);

    return SOFTBUS_OK;
}

int32_t TransPackReplyErrInfo(cJSON *msg, int errCode, const char* errDesc)
{
    TRANS_LOGI(TRANS_CTRL, "pack reply error info in negotiation.");
    if (msg == NULL || errDesc == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_ERR;
    }

    (void)AddNumberToJsonObject(msg, CODE, CODE_EXCHANGE_UDP_INFO);
    (void)AddStringToJsonObject(msg, ERR_DESC, errDesc);
    (void)AddNumberToJsonObject(msg, ERR_CODE, errCode);

    return SOFTBUS_OK;
}