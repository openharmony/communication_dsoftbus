/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "bus_center_manager.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_crypto.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_message_open_channel.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_session_account_adapter.h"
#include "trans_udp_channel_manager.h"
#include "trans_uk_manager.h"

#define BASE64_SESSION_KEY_LEN 45
typedef enum {
    CODE_EXCHANGE_UDP_INFO = 6,
    CODE_FILE_TRANS_UDP = 0x602
} CodeType;

#define ISHARE_SESSION_NAME "IShare*"

static inline CodeType getCodeType(const AppInfo *appInfo)
{
    return ((appInfo->udpConnType == UDP_CONN_TYPE_P2P || appInfo->udpConnType == UDP_CONN_TYPE_USB) &&
        CompareSessionName(ISHARE_SESSION_NAME, appInfo->myData.sessionName) &&
        CompareSessionName(ISHARE_SESSION_NAME, appInfo->peerData.sessionName)) ?
        CODE_FILE_TRANS_UDP : CODE_EXCHANGE_UDP_INFO;
}

int32_t TransUnpackReplyErrInfo(const cJSON *msg, int32_t *errCode)
{
    if (msg == NULL || errCode == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!GetJsonObjectInt32Item(msg, ERR_CODE, errCode)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransUnpackReplyUdpInfo(const cJSON *msg, AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "unpack reply udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    (void)GetJsonObjectStringItem(msg, "PKG_NAME", appInfo->peerData.pkgName, PKG_NAME_SIZE_MAX);
    (void)GetJsonObjectNumberItem(msg, "UID", &(appInfo->peerData.uid));
    (void)GetJsonObjectNumberItem(msg, "PID", &(appInfo->peerData.pid));
    (void)GetJsonObjectNumberItem(msg, "BUSINESS_TYPE", (int32_t *)&(appInfo->businessType));
    (void)GetJsonObjectNumberItem(msg, "API_VERSION", (int32_t *)&(appInfo->peerData.apiVersion));

    int32_t code = CODE_EXCHANGE_UDP_INFO;
    (void)GetJsonObjectNumberItem(msg, "CODE", &code);
    if ((code == CODE_FILE_TRANS_UDP) && (getCodeType(appInfo) == CODE_FILE_TRANS_UDP)) {
        appInfo->fileProtocol = APP_INFO_UDP_FILE_PROTOCOL;
    }
    if (!GetJsonObjectNumberItem(msg, "TRANS_CAPABILITY", (int32_t *)&(appInfo->channelCapability))) {
        appInfo->channelCapability = 0;
    }
    if (!GetJsonObjectNumberItem(msg, "UDP_CHANNEL_CAPABILITY", (int32_t *)&(appInfo->udpChannelCapability))) {
        appInfo->udpChannelCapability = 0;
    }
    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)GetJsonObjectNumber64Item(msg, "MY_CHANNEL_ID", &(appInfo->peerData.channelId));
            (void)GetJsonObjectNumberItem(msg, "MY_PORT", &(appInfo->peerData.port));
            (void)GetJsonObjectStringItem(msg, "MY_IP", appInfo->peerData.addr, sizeof(appInfo->peerData.addr));
            (void)GetJsonObjectStringItem(
                msg, "SINK_ACL_ACCOUNT_ID", (appInfo->peerData.accountId), ACCOUNT_UID_LEN_MAX);
            if (!GetJsonObjectNumberItem(msg, "SINK_ACL_USER_ID", &appInfo->peerData.userId)) {
                appInfo->peerData.userId = INVALID_USER_ID;
            }
            (void)GetJsonObjectNumber64Item(msg, "SINK_ACL_TOKEN_ID", (int64_t *)&appInfo->peerData.tokenId);
            if (DecryptAndAddSinkSessionKey(msg, appInfo) != SOFTBUS_OK) {
                return SOFTBUS_PARSE_JSON_ERR;
            }
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    return SOFTBUS_OK;
}

static void TransGetCommonUdpInfoFromJson(const cJSON *msg, AppInfo *appInfo)
{
    (void)GetJsonObjectStringItem(msg, "PKG_NAME", appInfo->peerData.pkgName, PKG_NAME_SIZE_MAX);
    (void)GetJsonObjectStringItem(msg, "BUS_NAME", appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX);
    (void)GetJsonObjectStringItem(msg, "CLIENT_BUS_NAME", appInfo->peerData.sessionName, SESSION_NAME_SIZE_MAX);
    (void)GetJsonObjectStringItem(msg, "GROUP_ID", appInfo->groupId, GROUP_ID_SIZE_MAX);

    (void)GetJsonObjectNumberItem(msg, "API_VERSION", (int32_t *)&(appInfo->peerData.apiVersion));
    (void)GetJsonObjectNumberItem(msg, "PID", &(appInfo->peerData.pid));
    (void)GetJsonObjectNumberItem(msg, "UID", &(appInfo->peerData.uid));
    (void)GetJsonObjectNumberItem(msg, "BUSINESS_TYPE", (int32_t *)&(appInfo->businessType));
    (void)GetJsonObjectNumberItem(msg, "STREAM_TYPE", (int32_t *)&(appInfo->streamType));
    (void)GetJsonObjectNumberItem(msg, "CHANNEL_TYPE", (int32_t *)&(appInfo->udpChannelOptType));
    (void)GetJsonObjectNumberItem(msg, "UDP_CONN_TYPE", (int32_t *)&(appInfo->udpConnType));
    (void)GetJsonObjectBoolItem(msg, "FORCE_GENERATE_UK", &(appInfo->forceGenerateUk));
}

static void TransGetUdpChannelOpenInfoFromJson(const cJSON *msg, AppInfo *appInfo)
{
    (void)GetJsonObjectNumber64Item(msg, "MY_CHANNEL_ID", &(appInfo->peerData.channelId));
    (void)GetJsonObjectStringItem(msg, "MY_IP", appInfo->peerData.addr, sizeof(appInfo->peerData.addr));
    if (!GetJsonObjectNumber64Item(msg, "CALLING_TOKEN_ID", (int64_t *)&appInfo->callingTokenId)) {
        appInfo->callingTokenId = TOKENID_NOT_SET;
    }
    (void)GetJsonObjectNumberItem(msg, "LINK_TYPE", &appInfo->linkType);
    if (!GetJsonObjectNumberItem(msg, "USER_ID", &appInfo->peerData.userId)) {
        appInfo->peerData.userId = INVALID_USER_ID;
    }
    (void)GetJsonObjectStringItem(msg, "DEVICE_ID", appInfo->peerData.deviceId, UUID_BUF_LEN);
    (void)GetJsonObjectStringItem(msg, "ACCOUNT_ID", appInfo->peerData.accountId, ACCOUNT_UID_LEN_MAX);
    (void)GetJsonObjectNumber64Item(msg, "SOURCE_ACL_TOKEN_ID", (int64_t *)&appInfo->peerData.tokenId);
    (void)GetJsonObjectStringItem(msg, "SOURCE_ACL_EXTRA_INFO", (appInfo->extraAccessInfo), EXTRA_ACCESS_INFO_LEN_MAX);
    (void)GetJsonObjectNumberItem(msg, "LINKED_CHANNEL_ID", &appInfo->linkedChannelId);
}

int32_t TransUnpackRequestUdpInfo(const cJSON *msg, AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "unpack request udp info in negotiation.");
    TRANS_CHECK_AND_RETURN_RET_LOGW(msg != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "Invalid param");
    TRANS_CHECK_AND_RETURN_RET_LOGW(appInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "Invalid param");
    unsigned char encodeSessionKey[BASE64_SESSION_KEY_LEN] = { 0 };
    size_t len = 0;
    (void)GetJsonObjectStringItem(msg, "SESSION_KEY", (char *)encodeSessionKey, BASE64_SESSION_KEY_LEN);
    if (strlen((char *)encodeSessionKey) != 0) {
        int32_t ret = SoftBusBase64Decode((unsigned char *)appInfo->sessionKey, sizeof(appInfo->sessionKey), &len,
            (unsigned char *)encodeSessionKey, strlen((char *)encodeSessionKey));
        (void)memset_s(encodeSessionKey, sizeof(encodeSessionKey), 0, sizeof(encodeSessionKey));
        TRANS_CHECK_AND_RETURN_RET_LOGE(
            len == sizeof(appInfo->sessionKey), SOFTBUS_DECRYPT_ERR, TRANS_CTRL, "mbedtls decode failed.");
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_DECRYPT_ERR, TRANS_CTRL, "mbedtls decode failed.");
    }

    TransGetCommonUdpInfoFromJson(msg, appInfo);

    int32_t code = CODE_EXCHANGE_UDP_INFO;
    (void)GetJsonObjectNumberItem(msg, "CODE", &code);
    if ((code == CODE_FILE_TRANS_UDP) && (getCodeType(appInfo) == CODE_FILE_TRANS_UDP)) {
        appInfo->fileProtocol = APP_INFO_UDP_FILE_PROTOCOL;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            TransGetUdpChannelOpenInfoFromJson(msg, appInfo);
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            (void)GetJsonObjectNumber64Item(msg, "PEER_CHANNEL_ID", &(appInfo->myData.channelId));
            (void)GetJsonObjectNumber64Item(msg, "MY_CHANNEL_ID", &(appInfo->peerData.channelId));
            (void)GetJsonObjectStringItem(msg, "MY_IP", appInfo->peerData.addr, sizeof(appInfo->peerData.addr));
            if (appInfo->myData.channelId == INVALID_CHANNEL_ID) {
                (void)TransUdpGetChannelIdByAddr(appInfo);
            }
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    uint32_t remoteCapability = 0;
    (void)GetJsonObjectNumberItem(msg, "TRANS_CAPABILITY", (int32_t *)&remoteCapability);
    appInfo->channelCapability = remoteCapability & TRANS_CHANNEL_CAPABILITY;
    uint32_t remoteUdpChannelCapability = 0;
    (void)GetJsonObjectNumberItem(msg, "UDP_CHANNEL_CAPABILITY", (int32_t *)&remoteUdpChannelCapability);
    appInfo->udpChannelCapability = remoteUdpChannelCapability & TRANS_UDP_CHANNEL_CAPBILITY;
    TRANS_LOGW(TRANS_CTRL,
        "TransUnpackRequestUdpInfo UDP_CHANNEL_CAPABILITY=%{public}u, remoteUdpChannelCapability=%{public}u",
        appInfo->udpChannelCapability, remoteUdpChannelCapability);
    return SOFTBUS_OK;
}

static void TransAddInfoToUdpChannelOpenMsg(cJSON *msg, const AppInfo *appInfo)
{
    (void)AddNumber64ToJsonObject(msg, "MY_CHANNEL_ID", appInfo->myData.channelId);
    (void)AddStringToJsonObject(msg, "MY_IP", appInfo->myData.addr);
    (void)AddNumber64ToJsonObject(msg, "CALLING_TOKEN_ID", (int64_t)appInfo->callingTokenId);
    (void)AddNumberToJsonObject(msg, "LINK_TYPE", appInfo->linkType);
    (void)AddStringToJsonObject(msg, "DEVICE_ID", appInfo->myData.deviceId);
    (void)AddNumberToJsonObject(msg, "USER_ID", appInfo->myData.userId);
    (void)AddStringToJsonObject(msg, "ACCOUNT_ID", appInfo->myData.accountId);
    (void)AddNumber64ToJsonObject(msg, "SOURCE_ACL_TOKEN_ID", (int64_t)appInfo->myData.tokenId);
    (void)AddStringToJsonObject(msg, "SOURCE_ACL_EXTRA_INFO", appInfo->extraAccessInfo);
}

int32_t TransPackRequestUdpInfo(cJSON *msg, const AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "pack request udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            TransAddInfoToUdpChannelOpenMsg(msg, appInfo);
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            (void)AddNumber64ToJsonObject(msg, "PEER_CHANNEL_ID", appInfo->peerData.channelId);
            (void)AddNumber64ToJsonObject(msg, "MY_CHANNEL_ID", appInfo->myData.channelId);
            (void)AddStringToJsonObject(msg, "MY_IP", appInfo->myData.addr);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    char encodeSessionKey[BASE64_SESSION_KEY_LEN] = { 0 };
    size_t len = 0;
    int32_t ret = SoftBusBase64Encode((unsigned char *)encodeSessionKey, BASE64_SESSION_KEY_LEN, &len,
        (unsigned char *)appInfo->sessionKey, sizeof(appInfo->sessionKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "mbedtls base64 encode failed.");
        return SOFTBUS_DECRYPT_ERR;
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
    (void)memset_s(encodeSessionKey, sizeof(encodeSessionKey), 0, sizeof(encodeSessionKey));
    (void)AddNumberToJsonObject(msg, "TRANS_CAPABILITY", (int32_t)appInfo->channelCapability);
    (void)AddBoolToJsonObject(msg, "FORCE_GENERATE_UK", appInfo->forceGenerateUk);
    (void)AddNumberToJsonObject(msg, "UDP_CHANNEL_CAPABILITY", (int32_t)appInfo->udpChannelCapability);
    (void)AddNumberToJsonObject(msg, "LINKED_CHANNEL_ID", (int32_t)appInfo->linkedChannelId);

    return SOFTBUS_OK;
}

int32_t TransPackReplyUdpInfo(cJSON *msg, const AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "pack reply udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)AddNumber64ToJsonObject(msg, "MY_CHANNEL_ID", appInfo->myData.channelId);
            (void)AddNumberToJsonObject(msg, "MY_PORT", appInfo->myData.port);
            (void)AddStringToJsonObject(msg, "MY_IP", appInfo->myData.addr);
            (void)AddStringToJsonObject(msg, "SINK_ACL_ACCOUNT_ID", appInfo->myData.accountId);
            (void)AddNumberToJsonObject(msg, "SINK_ACL_USER_ID", appInfo->myData.userId);
            (void)AddNumber64ToJsonObject(msg, "SINK_ACL_TOKEN_ID", (int64_t)appInfo->myData.tokenId);
            if (EncryptAndAddSinkSessionKey(msg, appInfo) != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "Failed to encrypt sink session key.");
                return SOFTBUS_ENCRYPT_ERR;
            }
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }

    (void)AddNumberToJsonObject(msg, "CODE", getCodeType(appInfo));
    (void)AddStringToJsonObject(msg, "PKG_NAME", appInfo->myData.pkgName);
    (void)AddNumberToJsonObject(msg, "UID", appInfo->myData.uid);
    (void)AddNumberToJsonObject(msg, "PID", appInfo->myData.pid);
    (void)AddNumberToJsonObject(msg, "BUSINESS_TYPE", appInfo->businessType);
    (void)AddNumberToJsonObject(msg, "STREAM_TYPE", appInfo->streamType);
    (void)AddNumberToJsonObject(msg, "API_VERSION", (int32_t)appInfo->myData.apiVersion);
    (void)AddNumberToJsonObject(msg, "TRANS_CAPABILITY", (int32_t)appInfo->channelCapability);
    (void)AddNumberToJsonObject(msg, "UDP_CHANNEL_CAPABILITY", (int32_t)appInfo->udpChannelCapability);
    return SOFTBUS_OK;
}

int32_t TransPackReplyErrInfo(cJSON *msg, int32_t errCode, const char *errDesc)
{
    TRANS_LOGI(TRANS_CTRL, "pack reply error info in negotiation.");
    if (msg == NULL || errDesc == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    (void)AddNumberToJsonObject(msg, CODE, CODE_EXCHANGE_UDP_INFO);
    (void)AddStringToJsonObject(msg, ERR_DESC, errDesc);
    (void)AddNumberToJsonObject(msg, ERR_CODE, errCode);

    return SOFTBUS_OK;
}

static int32_t TransPackHASpecificData(const AppInfo *appInfo, cJSON *msg)
{
    unsigned char encodeSessionKey[BASE64_SESSION_KEY_LEN] = { 0 };
    size_t keyLen = 0;
    int32_t ret = SoftBusBase64Encode(
        encodeSessionKey, BASE64_SESSION_KEY_LEN, &keyLen, (unsigned char *)appInfo->sessionKey, SESSION_KEY_LENGTH);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "base64 encode failed ret=%{public}d", ret);
        return ret;
    }

    (void)AddStringToJsonObject(msg, "SESSION_KEY", (char *)encodeSessionKey);
    (void)memset_s(encodeSessionKey, sizeof(encodeSessionKey), 0, sizeof(encodeSessionKey));
    return SOFTBUS_OK;
}

static int32_t TransPackMetaTypeSpecificData(const AppInfo *appInfo, cJSON *msg)
{
    int32_t ret = SOFTBUS_OK;
    switch (appInfo->metaType) {
        case META_SDK:
        case META_HA: {
            ret = TransPackHASpecificData(appInfo, msg);
            break;
        }
        default: {
            TRANS_LOGE(TRANS_CTRL, "invalid metaType=%{public}d", appInfo->metaType);
            ret = SOFTBUS_FUNC_NOT_SUPPORT;
            break;
        }
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "pack specific data by metaType=%{public}d failed, ret=%{public}d", appInfo->metaType, ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t TransPackExtDeviceRequestInfo(cJSON *msg, const AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "pack request udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)AddNumber64ToJsonObject(msg, "MY_CHANNEL_ID", appInfo->myData.channelId);
            (void)AddStringToJsonObject(msg, "MY_IP", appInfo->myData.addr);
            (void)AddStringToJsonObject(msg, "DEVICE_ID", appInfo->myData.deviceId);
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            (void)AddNumber64ToJsonObject(msg, "PEER_CHANNEL_ID", appInfo->peerData.channelId);
            (void)AddNumber64ToJsonObject(msg, "MY_CHANNEL_ID", appInfo->myData.channelId);
            (void)AddStringToJsonObject(msg, "MY_IP", appInfo->myData.addr);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    int32_t ret = TransPackMetaTypeSpecificData(appInfo, msg);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "pack specific data failed");
    (void)AddNumberToJsonObject(msg, "CODE", getCodeType(appInfo));
    (void)AddNumberToJsonObject(msg, "API_VERSION", appInfo->myData.apiVersion);
    (void)AddNumberToJsonObject(msg, "CHANNEL_TYPE", appInfo->udpChannelOptType);
    (void)AddNumberToJsonObject(msg, "STREAM_TYPE", appInfo->streamType);
    (void)AddNumberToJsonObject(msg, "UDP_CONN_TYPE", appInfo->udpConnType);

    (void)AddStringToJsonObject(msg, "BUS_NAME", appInfo->peerData.sessionName);
    (void)AddNumberToJsonObject(msg, "BUSINESS_TYPE", appInfo->businessType);
    (void)AddStringToJsonObject(msg, "CLIENT_BUS_NAME", appInfo->myData.sessionName);
    (void)AddStringToJsonObject(msg, "PKG_NAME", appInfo->myData.pkgName);
    (void)AddNumberToJsonObject(msg, "TRANS_CAPABILITY", (int32_t)appInfo->channelCapability);
    (void)AddNumberToJsonObject(msg, "UDP_CHANNEL_CAPABILITY", (int32_t)appInfo->udpChannelCapability);
    return SOFTBUS_OK;
}

static int32_t TransUnpackHASpecificData(const cJSON *msg, AppInfo *appInfo)
{
    char sessionKey[BASE64_SESSION_KEY_LEN] = { 0 };
    (void)GetJsonObjectStringItem(msg, SESSION_KEY, sessionKey, sizeof(sessionKey));
    if (strlen(sessionKey) != 0) {
        size_t len = 0;
        int32_t ret = SoftBusBase64Decode((unsigned char *)appInfo->sessionKey, SESSION_KEY_LENGTH, &len,
            (unsigned char *)sessionKey, strlen(sessionKey));
        (void)memset_s(sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
        if (len != SESSION_KEY_LENGTH) {
            TRANS_LOGE(TRANS_CTRL, "Failed to decode sessionKey ret=%{public}d, len=%{public}zu", ret, len);
            return SOFTBUS_PARSE_JSON_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t TransUnpackMetaTypeSpecificData(const cJSON *msg, AppInfo *appInfo)
{
    int32_t ret = LnnGetRemoteNumInfo(appInfo->peerData.deviceId, NUM_KEY_META_TYPE, &appInfo->metaType);
    if (ret != SOFTBUS_OK) {
        char *anonymizeMetaNodeId = NULL;
        Anonymize(appInfo->peerData.deviceId, &anonymizeMetaNodeId);
        TRANS_LOGW(TRANS_CTRL, "get metaType by metaNodeId=%{public}s failed ret=%{public}d",
            AnonymizeWrapper(anonymizeMetaNodeId), ret);
        AnonymizeFree(anonymizeMetaNodeId);
    }

    switch (appInfo->metaType) {
        case META_SDK:
        case META_HA: {
            ret = TransUnpackHASpecificData(msg, appInfo);
            break;
        }
        default: {
            TRANS_LOGW(TRANS_CTRL, "invalid metaType=%{public}d, maybe old HA version", appInfo->metaType);
            ret = TransUnpackHASpecificData(msg, appInfo);
            if (ret == SOFTBUS_OK) {
                appInfo->metaType = META_HA;
            }
            break;
        }
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "unpack specific data by metaType=%{public}d failed, ret=%{public}d", appInfo->metaType, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransUnpackExtDeviceRequestInfo(const cJSON *msg, AppInfo *appInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGW(msg != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "Invalid param");
    TRANS_CHECK_AND_RETURN_RET_LOGW(appInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "Invalid param");
    (void)GetJsonObjectNumberItem(msg, "CHANNEL_TYPE", (int32_t *)&(appInfo->udpChannelOptType));
    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)GetJsonObjectNumber64Item(msg, "MY_CHANNEL_ID", &(appInfo->peerData.channelId));
            (void)GetJsonObjectStringItem(msg, "MY_IP", appInfo->peerData.addr, sizeof(appInfo->peerData.addr));
            (void)GetJsonObjectStringItem(msg, "DEVICE_ID", appInfo->peerData.deviceId, UUID_BUF_LEN);
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            (void)GetJsonObjectNumber64Item(msg, "PEER_CHANNEL_ID", &(appInfo->myData.channelId));
            (void)GetJsonObjectNumber64Item(msg, "MY_CHANNEL_ID", &(appInfo->peerData.channelId));
            (void)GetJsonObjectStringItem(msg, "MY_IP", appInfo->peerData.addr, sizeof(appInfo->peerData.addr));
            if (appInfo->myData.channelId == INVALID_CHANNEL_ID) {
                (void)TransUdpGetChannelIdByAddr(appInfo);
            }
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    (void)GetJsonObjectNumberItem(msg, "API_VERSION", (int32_t *)&(appInfo->peerData.apiVersion));
    (void)GetJsonObjectNumberItem(msg, "BUSINESS_TYPE", (int32_t *)&(appInfo->businessType));
    (void)GetJsonObjectStringItem(msg, "CLIENT_BUS_NAME", appInfo->peerData.sessionName, SESSION_NAME_SIZE_MAX);
    (void)GetJsonObjectNumberItem(msg, "STREAM_TYPE", (int32_t *)&(appInfo->streamType));
    (void)GetJsonObjectNumberItem(msg, "UDP_CONN_TYPE", (int32_t *)&(appInfo->udpConnType));
    (void)GetJsonObjectStringItem(msg, "BUS_NAME", appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX);
    (void)GetJsonObjectStringItem(msg, "PKG_NAME", appInfo->peerData.pkgName, PKG_NAME_SIZE_MAX);
    int32_t code = CODE_EXCHANGE_UDP_INFO;
    (void)GetJsonObjectNumberItem(msg, "CODE", &code);
    appInfo->fileProtocol = 0;
    uint32_t remoteCapability = 0;
    uint32_t remoteUdpChannelCapability = 0;
    (void)GetJsonObjectNumberItem(msg, "TRANS_CAPABILITY", (int32_t *)&remoteCapability);
    (void)GetJsonObjectNumberItem(msg, "UDP_CHANNEL_CAPABILITY", (int32_t *)&remoteUdpChannelCapability);
    int32_t ret = TransUnpackMetaTypeSpecificData(msg, appInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "Failed to unpack specific data.");
    appInfo->channelCapability = remoteCapability & TRANS_CHANNEL_CAPABILITY;
    appInfo->peerData.userId = INVALID_USER_ID;
    return SOFTBUS_OK;
}

int32_t TransPackExtDeviceReplyInfo(cJSON *msg, const AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "pack reply udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)AddNumber64ToJsonObject(msg, "MY_CHANNEL_ID", appInfo->myData.channelId);
            (void)AddNumberToJsonObject(msg, "P2P_PORT", appInfo->myData.port);
            (void)AddStringToJsonObject(msg, "MY_IP", appInfo->myData.addr);
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }

    (void)AddNumberToJsonObject(msg, "CODE", getCodeType(appInfo));
    (void)AddNumberToJsonObject(msg, "STREAM_TYPE", appInfo->streamType);
    (void)AddStringToJsonObject(msg, "PKG_NAME", appInfo->myData.pkgName);
    (void)AddNumberToJsonObject(msg, "BUSINESS_TYPE", appInfo->businessType);
    (void)AddNumberToJsonObject(msg, "API_VERSION", (int32_t)appInfo->myData.apiVersion);
    (void)AddNumberToJsonObject(msg, "TRANS_CAPABILITY", (int32_t)appInfo->channelCapability);
    (void)AddNumberToJsonObject(msg, "UDP_CHANNEL_CAPABILITY", (int32_t)appInfo->udpChannelCapability);
    return SOFTBUS_OK;
}

int32_t TransUnpackExtDeviceReplyInfo(const cJSON *msg, AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "unpack reply udp info in negotiation.");
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            (void)GetJsonObjectNumber64Item(msg, "MY_CHANNEL_ID", &(appInfo->peerData.channelId));
            (void)GetJsonObjectNumberItem(msg, "P2P_PORT", &(appInfo->peerData.port));
            (void)GetJsonObjectStringItem(msg, "MY_IP", appInfo->peerData.addr, sizeof(appInfo->peerData.addr));
            break;
        case TYPE_UDP_CHANNEL_CLOSE:
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    int32_t code = CODE_EXCHANGE_UDP_INFO;
    (void)GetJsonObjectNumberItem(msg, "CODE", &code);
    appInfo->fileProtocol = 0;
    (void)GetJsonObjectStringItem(msg, "PKG_NAME", appInfo->peerData.pkgName, PKG_NAME_SIZE_MAX);
    (void)GetJsonObjectNumberItem(msg, "BUSINESS_TYPE", (int32_t *)&(appInfo->businessType));
    (void)GetJsonObjectNumberItem(msg, "API_VERSION", (int32_t *)&(appInfo->peerData.apiVersion));
    (void)GetJsonObjectNumberItem(msg, "STREAM_TYPE", (int32_t *)&(appInfo->streamType));
    if (!GetJsonObjectNumberItem(msg, "TRANS_CAPABILITY", (int32_t *)&(appInfo->channelCapability))) {
        appInfo->channelCapability = 0;
    }
    if (!GetJsonObjectNumberItem(msg, "UDP_CHANNEL_CAPABILITY", (int32_t *)&(appInfo->udpChannelCapability))) {
        appInfo->udpChannelCapability = 0;
    }
    return SOFTBUS_OK;
}
