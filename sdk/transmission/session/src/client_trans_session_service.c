/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "client_trans_session_service.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "securec.h"
#include <unistd.h>

#include "anonymizer.h"
#include "client_qos_manager.h"
#include "client_trans_channel_manager.h"
#include "client_trans_file_listener.h"
#include "client_trans_session_adapter.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "dfs_session.h"
#include "inner_session.h"
#include "session_ipc_adapter.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_trans_def.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

typedef int (*SessionOptionRead)(int32_t channelId, int32_t type, void* value, uint32_t valueSize);
typedef int (*SessionOptionWrite)(int32_t channelId, int32_t type, void* value, uint32_t valueSize);

typedef struct {
    bool canRead;
    SessionOptionRead readFunc;
} SessionOptionItem;

typedef struct {
    int32_t channelType;
    int32_t businessType;
    ConfigType configType;
} ConfigTypeMap;

static bool IsValidSessionId(int sessionId)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId=%{public}d", sessionId);
        return false;
    }
    return true;
}

static bool IsValidListener(const ISessionListener *listener)
{
    if ((listener != NULL) &&
        (listener->OnSessionOpened != NULL) &&
        (listener->OnSessionClosed != NULL)) {
        return true;
    }
    TRANS_LOGE(TRANS_SDK, "invalid ISessionListener");
    return false;
}

static int32_t OpenSessionWithExistSession(int32_t sessionId, bool isEnabled)
{
    if (!isEnabled) {
        int32_t errCode = SOFTBUS_TRANS_SESSION_OPENING;
        TRANS_LOGI(TRANS_SDK, "the channel is opening, errCode=%{public}d", errCode);
        return sessionId;
    }

    ISessionListener listener = { 0 };
    int32_t ret = ClientGetSessionCallbackById(sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get session listener failed, ret=%{public}d", ret);
        CloseSession(sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    ret = listener.OnSessionOpened(sessionId, SOFTBUS_OK);
    if (ret != 0) {
        TRANS_LOGE(TRANS_SDK, "session callback OnSessionOpened failed, ret=%{public}d", ret);
        CloseSession(sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    return sessionId;
}

int CreateSessionServer(const char *pkgName, const char *sessionName, const ISessionListener *listener)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1) ||
        !IsValidListener(listener)) {
        TRANS_LOGW(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "pkgName=%{public}s, sessionName=%{public}s", pkgName, AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "init softbus err");
        return SOFTBUS_TRANS_SESSION_ADDPKG_FAILED;
    }

    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "invalid pkg name");
        return SOFTBUS_INVALID_PKGNAME;
    }

    int ret = ClientAddSessionServer(SEC_TYPE_CIPHERTEXT, pkgName, sessionName, listener);
    if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
        TRANS_LOGI(TRANS_SDK, "SessionServer is already created in client");
    } else if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add session server err, ret=%{public}d.", ret);
        return ret;
    }

    ret = ServerIpcCreateSessionServer(pkgName, sessionName);
    if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
        TRANS_LOGW(TRANS_SDK, "ok, SessionServer is already created in server");
        return SOFTBUS_OK;
    } else if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "createSessionServer failed, ret=%{public}d", ret);
        (void)ClientDeleteSessionServer(SEC_TYPE_CIPHERTEXT, sessionName);
        return ret;
    }
    TRANS_LOGI(TRANS_SDK, "ok");
    return ret;
}

int RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        TRANS_LOGW(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "pkgName=%{public}s, sessionName=%{public}s", pkgName, AnonymizeWrapper(tmpName));

    int32_t ret = ServerIpcRemoveSessionServer(pkgName, sessionName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "remove in server failed, ret=%{public}d.", ret);
        AnonymizeFree(tmpName);
        return ret;
    }

    ret = ClientDeleteSessionServer(SEC_TYPE_CIPHERTEXT, sessionName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "delete session server failed, sessionName=%{public}s, ret=%{public}d.",
            AnonymizeWrapper(tmpName), ret);
        DeleteFileListener(sessionName);
        AnonymizeFree(tmpName);
        return ret;
    }
    DeleteFileListener(sessionName);
    AnonymizeFree(tmpName);
    TRANS_LOGI(TRANS_SDK, "ok");
    return ret;
}

static int32_t CheckParamIsValid(const char *mySessionName, const char *peerSessionName,
    const char *peerNetworkId, const char *groupId, const SessionAttribute *attr)
{
    if (!IsValidString(mySessionName, SESSION_NAME_SIZE_MAX - 1)) {
        char *tmpMyName = NULL;
        Anonymize(mySessionName, &tmpMyName);
        TRANS_LOGE(TRANS_SDK, "invalid mySessionName. tmpMyName=%{public}s", AnonymizeWrapper(tmpMyName));
        AnonymizeFree(tmpMyName);
        return SOFTBUS_TRANS_INVALID_SESSION_NAME;
    }
    if (!IsValidString(peerSessionName, SESSION_NAME_SIZE_MAX - 1)) {
        char *tmpPeerName = NULL;
        Anonymize(peerSessionName, &tmpPeerName);
        TRANS_LOGE(TRANS_SDK, "invalid peerSessionName. tmpPeerName=%{public}s", AnonymizeWrapper(tmpPeerName));
        AnonymizeFree(tmpPeerName);
        return SOFTBUS_TRANS_INVALID_SESSION_NAME;
    }
    if (!IsValidString(peerNetworkId, DEVICE_ID_SIZE_MAX - 1)) {
        char *tmpPeerNetworkId = NULL;
        Anonymize(peerNetworkId, &tmpPeerNetworkId);
        TRANS_LOGE(TRANS_SDK, "invalid peerNetworkId. tmpPeerNetworkId=%{public}s", AnonymizeWrapper(tmpPeerNetworkId));
        AnonymizeFree(tmpPeerNetworkId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (attr == NULL) {
        TRANS_LOGE(TRANS_SDK, "attr is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (groupId == NULL) {
        TRANS_LOGE(TRANS_SDK, "groupId is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strlen(groupId) >= GROUP_ID_SIZE_MAX) {
        TRANS_LOGE(TRANS_SDK, "groupId length is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

static void PrintSessionName(const char *mySessionName, const char *peerSessionName)
{
    char *tmpMyName = NULL;
    char *tmpPeerName = NULL;
    Anonymize(mySessionName, &tmpMyName);
    Anonymize(peerSessionName, &tmpPeerName);
    TRANS_LOGI(TRANS_SDK, "OpenSession: mySessionName=%{public}s, peerSessionName=%{public}s",
        AnonymizeWrapper(tmpMyName), AnonymizeWrapper(tmpPeerName));
    AnonymizeFree(tmpMyName);
    AnonymizeFree(tmpPeerName);
}

static SessionAttribute *BuildParamSessionAttribute(const SessionAttribute *attr)
{
    SessionAttribute *tmpAttr = (SessionAttribute *)SoftBusCalloc(sizeof(SessionAttribute));
    if (tmpAttr == NULL) {
        TRANS_LOGE(TRANS_SDK, "SoftBusCalloc SessionAttribute failed");
        return NULL;
    }
    if (memcpy_s(tmpAttr, sizeof(SessionAttribute), attr, sizeof(SessionAttribute)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy_s SessionAttribute failed");
        SoftBusFree(tmpAttr);
        return NULL;
    }
    tmpAttr->fastTransData = NULL;
    tmpAttr->fastTransDataSize = 0;
    return tmpAttr;
}

static void InitSessionParam(const char *mySessionName, const char *peerSessionName, const char *peerNetworkId,
    const char *groupId, SessionParam *param)
{
    param->sessionName = mySessionName;
    param->peerSessionName = peerSessionName;
    param->peerDeviceId = peerNetworkId;
    param->groupId = groupId;
    param->isQosLane = false;
    param->qosCount = 0;
    param->isAsync = false;
    param->actionId = INVALID_ACTION_ID;
}

int OpenSession(const char *mySessionName, const char *peerSessionName, const char *peerNetworkId,
    const char *groupId, const SessionAttribute *attr)
{
    int32_t ret = CheckParamIsValid(mySessionName, peerSessionName, peerNetworkId, groupId, attr);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "invalid session name.");

    PrintSessionName(mySessionName, peerSessionName);
    SessionAttribute *tmpAttr = BuildParamSessionAttribute(attr);
    TRANS_CHECK_AND_RETURN_RET_LOGE(tmpAttr != NULL, SOFTBUS_MEM_ERR, TRANS_SDK, "Build SessionAttribute failed.");
    SessionParam param = { 0 };
    InitSessionParam(mySessionName, peerSessionName, peerNetworkId, groupId, &param);
    param.attr = tmpAttr;
    (void)memset_s(param.qos, sizeof(param.qos), 0, sizeof(param.qos));

    int32_t sessionId = INVALID_SESSION_ID;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;

    ret = ClientAddSession(&param, &sessionId, &isEnabled);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(tmpAttr);
        if (ret == SOFTBUS_TRANS_SESSION_REPEATED) {
            TRANS_LOGI(TRANS_SDK, "session already opened");
            return OpenSessionWithExistSession(sessionId, isEnabled);
        }
        TRANS_LOGE(TRANS_SDK, "add session err: ret=%{public}d", ret);
        return ret;
    }
    param.isAsync = false;
    param.sessionId = sessionId;
    TransInfo transInfo = { 0 };
    ret = ServerIpcOpenSession(&param, &transInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "open session ipc err: ret=%{public}d", ret);
        SoftBusFree(tmpAttr);
        (void)ClientDeleteSession(sessionId);
        return ret;
    }

    ret = ClientSetChannelBySessionId(sessionId, &transInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set channel by sessionId failed, ret=%{public}d", ret);
        SoftBusFree(tmpAttr);
        (void)ClientDeleteSession(sessionId);
        return SOFTBUS_TRANS_SESSION_SET_CHANNEL_FAILED;
    }
    TRANS_LOGI(TRANS_SDK, "ok: sessionId=%{public}d, channelId=%{public}d, channelType=%{public}d",
        sessionId, transInfo.channelId, transInfo.channelType);
    SoftBusFree(tmpAttr);
    return sessionId;
}

static int32_t ConvertAddrStr(const char *addrStr, ConnectionAddr *addrInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        (addrStr != NULL && addrInfo != NULL), SOFTBUS_INVALID_PARAM, TRANS_SDK, "invalid param");
    cJSON *obj = cJSON_Parse(addrStr);
    TRANS_CHECK_AND_RETURN_RET_LOGE(obj != NULL, SOFTBUS_PARSE_JSON_ERR, TRANS_SDK, "addrStr parse failed.");
    int32_t port;
    if (GetJsonObjectStringItem(obj, "ETH_IP", addrInfo->info.ip.ip, IP_STR_MAX_LEN) &&
        GetJsonObjectNumberItem(obj, "ETH_PORT", &port)) {
        addrInfo->info.ip.port = (uint16_t)port;
        if (IsValidString(addrInfo->info.ip.ip, IP_STR_MAX_LEN) && addrInfo->info.ip.port > 0) {
            cJSON_Delete(obj);
            addrInfo->type = CONNECTION_ADDR_ETH;
            return SOFTBUS_OK;
        }
    }
    if (GetJsonObjectStringItem(obj, "WIFI_IP", addrInfo->info.ip.ip, IP_STR_MAX_LEN) &&
        GetJsonObjectNumberItem(obj, "WIFI_PORT", &port)) {
        addrInfo->info.ip.port = (uint16_t)port;
        if (IsValidString(addrInfo->info.ip.ip, IP_STR_MAX_LEN) && addrInfo->info.ip.port > 0) {
            cJSON_Delete(obj);
            addrInfo->type = CONNECTION_ADDR_WLAN;
            return SOFTBUS_OK;
        }
    }
    if (GetJsonObjectStringItem(obj, "BR_MAC", addrInfo->info.br.brMac, BT_MAC_LEN)) {
        cJSON_Delete(obj);
        addrInfo->type = CONNECTION_ADDR_BR;
        return SOFTBUS_OK;
    }
    if (GetJsonObjectStringItem(obj, "BLE_MAC", addrInfo->info.ble.bleMac, BT_MAC_LEN)) {
        char udidHash[UDID_HASH_LEN] = {0};
        if (GetJsonObjectStringItem(obj, "deviceId", udidHash, UDID_HASH_LEN)) {
            char *tmpUdidHash = NULL;
            Anonymize(udidHash, &tmpUdidHash);
            int ret = ConvertHexStringToBytes(
                (unsigned char *)addrInfo->info.ble.udidHash, UDID_HASH_LEN, udidHash, strlen(udidHash));
            TRANS_LOGI(TRANS_SDK, "string to bytes ret=%{public}d, udidHash=%{public}s",
                ret, AnonymizeWrapper(tmpUdidHash));
            AnonymizeFree(tmpUdidHash);
        }
        cJSON_Delete(obj);
        addrInfo->type = CONNECTION_ADDR_BLE;
        return SOFTBUS_OK;
    }
    cJSON_Delete(obj);
    TRANS_LOGE(TRANS_SDK, "addr convert fail");
    return SOFTBUS_PARSE_JSON_ERR;
}

static int IsValidAddrInfoArr(const ConnectionAddr *addrInfo, int num)
{
    int32_t addrIndex = -1;
    if (addrInfo == NULL || num <= 0) {
        return addrIndex;
    }
    int32_t wifiIndex = -1;
    int32_t brIndex = -1;
    int32_t bleIndex = -1;
    for (int32_t index = 0; index < num; index++) {
        if ((addrInfo[index].type == CONNECTION_ADDR_ETH || addrInfo[index].type == CONNECTION_ADDR_WLAN) &&
            wifiIndex < 0) {
            wifiIndex = index;
        }
        if (addrInfo[index].type == CONNECTION_ADDR_BR && brIndex < 0) {
            brIndex = index;
        }
        if (addrInfo[index].type == CONNECTION_ADDR_BLE && bleIndex < 0) {
            bleIndex = index;
        }
    }
    addrIndex = (wifiIndex >= 0) ? wifiIndex : addrIndex;
    addrIndex = (addrIndex < 0) ? brIndex : addrIndex;
    addrIndex = (addrIndex < 0) ? bleIndex : addrIndex;
    return addrIndex;
}

int OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo, int num, const char *mixAddr)
{
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        TRANS_LOGW(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TransInfo transInfo;
    int32_t addrIndex = IsValidAddrInfoArr(addrInfo, num);
    ConnectionAddr *addr = NULL;
    ConnectionAddr mix;
    if (memset_s(&mix, sizeof(ConnectionAddr), 0x0, sizeof(ConnectionAddr)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memset_s info fail");
        return SOFTBUS_MEM_ERR;
    }
    if (addrIndex < 0) {
        if (ConvertAddrStr(mixAddr, &mix) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "invalid addrInfo param");
            return SOFTBUS_INVALID_PARAM;
        }
        addr = &mix;
    } else {
        addr = (ConnectionAddr *)&addrInfo[addrIndex];
    }
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    int32_t sessionId;
    int32_t ret = ClientAddAuthSession(sessionName, &sessionId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add non encrypt session err: ret=%{public}d", ret);
        return ret;
    }

    transInfo.channelId = ServerIpcOpenAuthSession(sessionName, addr);
    if (addr->type == CONNECTION_ADDR_BR || addr->type == CONNECTION_ADDR_BLE) {
        transInfo.channelType = CHANNEL_TYPE_PROXY;
    } else {
        transInfo.channelType = CHANNEL_TYPE_AUTH;
    }
    ret = ClientSetChannelBySessionId(sessionId, &transInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set channel by sessionId failed, ret=%{public}d", ret);
        (void)ClientDeleteSession(sessionId);
        return SOFTBUS_TRANS_SESSION_SET_CHANNEL_FAILED;
    }
    TRANS_LOGI(TRANS_SDK, "ok: sessionId=%{public}d, channelId=%{public}d, channelType=%{public}d",
        sessionId, transInfo.channelId, transInfo.channelType);
    return sessionId;
}

void NotifyAuthSuccess(int sessionId)
{
    int32_t channelId = -1;
    int32_t channelType = -1;
    TRANS_LOGI(TRANS_SDK, "sessionId=%{public}d", sessionId);
    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &channelType, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channel err, sessionId=%{public}d, ret=%{public}d", sessionId, ret);
        return;
    }

    int32_t isServer = 0;
    ret = ClientGetSessionIntegerDataById(sessionId, &isServer, KEY_IS_SERVER);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get isServer failed, ret=%{public}d", ret);
        return;
    }
    if (isServer == 1) {
        TRANS_LOGE(TRANS_SDK, "device is service side, no notification");
        return;
    }
    TRANS_LOGI(TRANS_SDK,
        "client side, notify auth success channelId=%{public}d, channelType=%{public}d", channelId, channelType);

    ret = ServerIpcNotifyAuthSuccess(channelId, channelType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK,
            "ServerIpcNotifyAuthSuccess err channelId=%{public}d, ret=%{public}d", channelId, ret);
        return;
    }
}

static int32_t CheckSessionIsOpened(int32_t sessionId, bool isCancelCheck)
{
#define SESSION_STATUS_CHECK_MAX_NUM 100
#define SESSION_STATUS_CANCEL_CHECK_MAX_NUM 5
#define SESSION_CHECK_PERIOD 200000
    int32_t checkMaxNum = isCancelCheck ? SESSION_STATUS_CANCEL_CHECK_MAX_NUM : SESSION_STATUS_CHECK_MAX_NUM;
    int32_t i = 0;
    SessionEnableStatus enableStatus = ENABLE_STATUS_INIT;
    while (i < checkMaxNum) {
        if (ClientGetChannelBySessionId(sessionId, NULL, NULL, &enableStatus) != SOFTBUS_OK) {
            return SOFTBUS_TRANS_SESSION_GET_CHANNEL_FAILED;
        }
        if (enableStatus == ENABLE_STATUS_SUCCESS) {
            TRANS_LOGD(TRANS_SDK, "session is enable");
            return SOFTBUS_OK;
        }

        if (enableStatus == ENABLE_STATUS_FAILED) {
            TRANS_LOGE(TRANS_SDK, "socket is failed");
            return SOFTBUS_TRANS_SESSION_NO_ENABLE;
        }
        usleep(SESSION_CHECK_PERIOD);
        i++;
    }

    TRANS_LOGE(TRANS_SDK, "session open timeout");
    return SOFTBUS_TIMOUT;
}

int OpenSessionSync(const char *mySessionName, const char *peerSessionName, const char *peerNetworkId,
    const char *groupId, const SessionAttribute *attr)
{
    int ret = CheckParamIsValid(mySessionName, peerSessionName, peerNetworkId, groupId, attr);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "invalid session name.");
    PrintSessionName(mySessionName, peerSessionName);

    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerNetworkId,
        .groupId = groupId,
        .attr = attr,
        .isQosLane = false,
        .qosCount = 0,
    };
    (void)memset_s(param.qos, sizeof(param.qos), 0, sizeof(param.qos));

    int32_t sessionId = INVALID_SESSION_ID;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;

    ret = ClientAddSession(&param, &sessionId, &isEnabled);
    if (ret != SOFTBUS_OK) {
        if (ret == SOFTBUS_TRANS_SESSION_REPEATED) {
            TRANS_LOGI(TRANS_SDK, "session already opened");
            CheckSessionIsOpened(sessionId, false);
            return OpenSessionWithExistSession(sessionId, isEnabled);
        }
        TRANS_LOGE(TRANS_SDK, "add session err: ret=%{public}d", ret);
        return ret;
    }
    param.isAsync = false;
    param.sessionId = sessionId;
    TransInfo transInfo = {0};
    ret = ServerIpcOpenSession(&param, &transInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "open session ipc err: ret=%{public}d", ret);
        (void)ClientDeleteSession(sessionId);
        return ret;
    }
    ret = ClientSetChannelBySessionId(sessionId, &transInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set channel by sessionId=%{public}d, ret=%{public}d", sessionId, ret);
        (void)ClientDeleteSession(sessionId);
        return SOFTBUS_TRANS_SESSION_SET_CHANNEL_FAILED;
    }

    ret = CheckSessionIsOpened(sessionId, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "CheckSessionIsOpened err: ret=%{public}d", ret);
        (void)ClientDeleteSession(sessionId);
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    TRANS_LOGI(TRANS_SDK, "ok: sessionId=%{public}d, channelId=%{public}d", sessionId, transInfo.channelId);
    return sessionId;
}

void CloseSession(int sessionId)
{
    TRANS_LOGI(TRANS_SDK, "sessionId=%{public}d", sessionId);
    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    int32_t ret;

    if (!IsValidSessionId(sessionId)) {
        TRANS_LOGW(TRANS_SDK, "invalid param");
        return;
    }
    ret = ClientGetChannelBySessionId(sessionId, &channelId, &type, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channel by sessionId=%{public}d, ret=%{public}d", sessionId, ret);
        return;
    }
    AddSessionStateClosing();
    ret = ClientTransCloseChannel(channelId, type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "close channel err: ret=%{public}d, channelId=%{public}d, channelType=%{public}d",
            ret, channelId, type);
    }
    ret = ClientDeleteSession(sessionId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "delete session err: ret=%{public}d", ret);
        return;
    }
    TRANS_LOGD(TRANS_SDK, "ok");
}

int GetMySessionName(int sessionId, char *sessionName, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (sessionName == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_SDK, "get client sessionName by sessionId=%{public}d", sessionId);
    return ClientGetSessionDataById(sessionId, sessionName, len, KEY_SESSION_NAME);
}

int GetPeerSessionName(int sessionId, char *sessionName, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (sessionName == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_SDK, "get server sessionName by sessionId=%{public}d", sessionId);
    return ClientGetSessionDataById(sessionId, sessionName, len, KEY_PEER_SESSION_NAME);
}

int GetPeerDeviceId(int sessionId, char *networkId, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (networkId  == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_SDK, "get server deviceId by sessionId=%{public}d", sessionId);
    return ClientGetSessionDataById(sessionId, networkId, len, KEY_PEER_DEVICE_ID);
}

int GetSessionSide(int sessionId)
{
    TRANS_LOGI(TRANS_SDK, "get session side by sessionId=%{public}d", sessionId);
    return ClientGetSessionSide(sessionId);
}

static bool IsValidFileReceivePath(const char *rootDir)
{
    if (!IsValidString(rootDir, FILE_RECV_ROOT_DIR_SIZE_MAX)) {
        TRANS_LOGE(TRANS_SDK, "recvPath invalid. recvPath=%{private}s", rootDir);
        return false;
    }
    char *absPath = realpath(rootDir, NULL);
    if (absPath == NULL) {
        TRANS_LOGE(TRANS_SDK, "recvPath not exist, recvPath=%{private}s, errno=%{public}d.", rootDir, errno);
        return false;
    }
    SoftBusFree(absPath);
    return true;
}

int SetFileReceiveListener(const char *pkgName, const char *sessionName,
    const IFileReceiveListener *recvListener, const char *rootDir)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1) ||
        !IsValidFileReceivePath(rootDir) || (recvListener == NULL)) {
        TRANS_LOGW(TRANS_SDK, "set file receive listener invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set file receive listener init softbus client error");
        return SOFTBUS_TRANS_SESSION_ADDPKG_FAILED;
    }
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    return TransSetFileReceiveListener(sessionName, recvListener, rootDir);
}

int SetFileSendListener(const char *pkgName, const char *sessionName, const IFileSendListener *sendListener)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1) ||
        sendListener == NULL) {
        TRANS_LOGW(TRANS_SDK, "set file send listener invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set file send listener init softbus client error");
        return SOFTBUS_TRANS_SESSION_ADDPKG_FAILED;
    }
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    return TransSetFileSendListener(sessionName, sendListener);
}

static const char *g_busName = "DistributedFileService";
static const char *g_deviceStatusName = "ohos.msdp.device_status";

static int32_t IsValidDFSSession(int32_t sessionId, int32_t *channelId)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    int32_t type;
    int32_t ret = GetMySessionName(sessionId, sessionName, SESSION_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get dfs session name failed");
        return ret;
    }
    if (strncmp(sessionName, g_busName, strlen(g_busName)) != 0 &&
        strncmp(sessionName, g_deviceStatusName, strlen(g_deviceStatusName)) != 0) {
        TRANS_LOGE(TRANS_SDK, "invalid dfs session name");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }

    ret = ClientGetChannelBySessionId(sessionId, channelId, &type, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channel by sessionId=%{public}d failed, ret=%{public}d", sessionId, ret);
        return SOFTBUS_TRANS_SESSION_GET_CHANNEL_FAILED;
    }
    if (type != CHANNEL_TYPE_TCP_DIRECT) {
        TRANS_LOGE(TRANS_SDK, "invalid channel type");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }
    return SOFTBUS_OK;
}

int32_t GetSessionKey(int32_t sessionId, char *key, unsigned int len)
{
    int32_t channelId;
    if (!IsValidSessionId(sessionId) || key == NULL || len < SESSION_KEY_LEN) {
        TRANS_LOGW(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsValidDFSSession(sessionId, &channelId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "invalid dfs session");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }
    return ClientGetSessionKey(channelId, key, len);
}

int32_t GetSessionHandle(int32_t sessionId, int *handle)
{
    int32_t channelId;
    if (!IsValidSessionId(sessionId) || handle == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsValidDFSSession(sessionId, &channelId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "invalid dfs session");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }
    return ClientGetHandle(channelId, handle);
}

int32_t DisableSessionListener(int32_t sessionId)
{
    int32_t channelId;
    if (!IsValidSessionId(sessionId)) {
        TRANS_LOGW(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsValidDFSSession(sessionId, &channelId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "invalid dfs session");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }
    return ClientDisableSessionListener(channelId);
}

int32_t QosReport(int32_t sessionId, int32_t appType, int32_t quality)
{
    if (quality != QOS_IMPROVE && quality != QOS_RECOVER) {
        TRANS_LOGW(TRANS_SDK, "qos report invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &type, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channel by sessionId=%{public}d failed, ret=%{public}d.", sessionId, ret);
        return SOFTBUS_TRANS_SESSION_GET_CHANNEL_FAILED;
    }
    if (ClientGetSessionSide(sessionId) != IS_CLIENT) {
        TRANS_LOGE(TRANS_SDK,
            "qos report not exist or not client side. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    ret = ClientQosReport(channelId, type, appType, quality);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "qos report failed. sessionId=%{public}d, ret=%{public}d", sessionId, ret);
    }
    return ret;
}

static const ConfigTypeMap g_configTypeMap[] = {
    {CHANNEL_TYPE_AUTH, BUSINESS_TYPE_BYTE, SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH},
    {CHANNEL_TYPE_AUTH, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH},
    {CHANNEL_TYPE_PROXY, BUSINESS_TYPE_BYTE, SOFTBUS_INT_PROXY_MAX_BYTES_LENGTH},
    {CHANNEL_TYPE_PROXY, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_PROXY_MAX_MESSAGE_LENGTH},
    {CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_BYTE, SOFTBUS_INT_MAX_BYTES_LENGTH},
    {CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_LENGTH},
};

int32_t GetDefaultConfigType(int32_t channelType, int32_t businessType)
{
    const uint32_t nums = sizeof(g_configTypeMap) / sizeof(ConfigTypeMap);
    for (uint32_t i = 0; i < nums; i++) {
        if ((g_configTypeMap[i].channelType == channelType) &&
            (g_configTypeMap[i].businessType == businessType)) {
                return g_configTypeMap[i].configType;
            }
    }
    return SOFTBUS_CONFIG_TYPE_MAX;
}

int ReadMaxSendBytesSize(int32_t channelId, int32_t type, void* value, uint32_t valueSize)
{
    if (valueSize != sizeof(uint32_t)) {
        TRANS_LOGE(TRANS_SDK, "valueSize not match. valueSize=%{public}d", valueSize);
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t dataConfig = INVALID_DATA_CONFIG;
    if (ClientGetDataConfigByChannelId(channelId, type, &dataConfig) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get config failed.");
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }

    (*(uint32_t*)value) = dataConfig;
    return SOFTBUS_OK;
}

int ReadMaxSendMessageSize(int32_t channelId, int32_t type, void* value, uint32_t valueSize)
{
    if (value == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (valueSize != sizeof(uint32_t)) {
        TRANS_LOGE(TRANS_SDK, "valueSize not match. valueSize=%{public}d", valueSize);
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t dataConfig = INVALID_DATA_CONFIG;
    if (ClientGetDataConfigByChannelId(channelId, type, &dataConfig) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get config failed.");
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }

    (*(uint32_t*)value) = dataConfig;
    return SOFTBUS_OK;
}

int ReadSessionLinkType(int32_t channelId, int32_t type, void* value, uint32_t valueSize)
{
    if (value == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (valueSize != sizeof(uint32_t)) {
        TRANS_LOGE(TRANS_SDK, "valueSize not match. valueSize=%{public}d", valueSize);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t routeType = INVALID_ROUTE_TYPE;
    if (ClientGetRouteTypeByChannelId(channelId, type, &routeType) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get link type failed.");
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }

    (*(int32_t*)value) = routeType;
    return SOFTBUS_OK;
}

static const SessionOptionItem g_SessionOptionArr[SESSION_OPTION_BUTT] = {
    {true, ReadMaxSendBytesSize},
    {true, ReadMaxSendMessageSize},
    {true, ReadSessionLinkType},
};

int GetSessionOption(int sessionId, SessionOption option, void* optionValue, uint32_t valueSize)
{
    if ((option >= SESSION_OPTION_BUTT) || (optionValue == NULL) || (valueSize == 0)) {
        TRANS_LOGW(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_SessionOptionArr[option].canRead) {
        TRANS_LOGE(TRANS_SDK, "option can not be get. option=%{public}d", option);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &type, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channel by sessionId=%{public}d failed, ret=%{public}d.", sessionId, ret);
        return SOFTBUS_TRANS_SESSION_GET_CHANNEL_FAILED;
    }

    return g_SessionOptionArr[option].readFunc(channelId, type, optionValue, valueSize);
}

bool RemoveAppIdFromSessionName(const char *sessionName, char *newSessionName, int32_t length)
{
    if ((sessionName == NULL) || (newSessionName == NULL)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return false;
    }
    const char tag = '-';
    const char *posName = strchr(sessionName, tag);
    if (posName == NULL) {
        TRANS_LOGE(TRANS_SDK, "sdk not find bundlename");
        return false;
    }
    const char *posId = strchr(posName + 1, tag);
    if (posId == NULL) {
        TRANS_LOGE(TRANS_SDK, "sdk not find appid");
        return false;
    }
    size_t len = posId - sessionName;
    if (strncpy_s(newSessionName, length, sessionName, len) != EOK) {
        TRANS_LOGE(TRANS_SDK, "copy sessionName failed");
        return false;
    }
    newSessionName[len] = '\0';
    return true;
}

int CreateSocket(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        TRANS_LOGE(TRANS_SDK, "invalid pkgName or sessionName");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = InitSoftBus(pkgName);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, SOFTBUS_TRANS_SESSION_ADDPKG_FAILED, TRANS_SDK, "init softbus err");

    ret = CheckPackageName(pkgName);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_INVALID_PKGNAME, TRANS_SDK, "invalid pkg name");
    char newSessionName[SESSION_NAME_SIZE_MAX + 1] = {0};
    if (strncpy_s(newSessionName, SESSION_NAME_SIZE_MAX + 1, sessionName, strlen(sessionName)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "copy session name failed");
        return SOFTBUS_STRCPY_ERR;
    }
    uint64_t callingFullTokenId = 0;
    ret = SoftBusGetCallingFullTokenId(&callingFullTokenId);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get callingFullTokenId failed");

    if (SoftBusCheckIsNormalApp(callingFullTokenId, sessionName)) {
        if (!RemoveAppIdFromSessionName(sessionName, newSessionName, SESSION_NAME_SIZE_MAX + 1)) {
            TRANS_LOGE(TRANS_SDK, "invalid bundlename or appId and delete appId failed");
            return SOFTBUS_TRANS_NOT_FIND_APPID;
        }
    }
    ret = ClientAddSocketServer(SEC_TYPE_CIPHERTEXT, pkgName, (const char*)newSessionName);
    if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
        TRANS_LOGD(TRANS_SDK, "SocketServer is already created in client");
    } else if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add socket server err, ret=%{public}d", ret);
        return ret;
    }
    ret = ServerIpcCreateSessionServer(pkgName, sessionName);
    if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
        TRANS_LOGD(TRANS_SDK, "ok, SocketServer is already created in server");
        return SOFTBUS_OK;
    } else if (ret != SOFTBUS_OK) {
        SocketServerStateUpdate(newSessionName);
        TRANS_LOGE(TRANS_SDK, "createSocketServer failed, ret=%{public}d", ret);
        (void)ClientDeleteSessionServer(SEC_TYPE_CIPHERTEXT, newSessionName);
        return ret;
    }
    TRANS_LOGD(TRANS_SDK, "ok");
    return SOFTBUS_OK;
}

static SessionAttribute *CreateSessionAttributeBySocketInfoTrans(const SocketInfo *info, bool *isEncyptedRawStream)
{
    SessionAttribute *tmpAttr = (SessionAttribute *)SoftBusCalloc(sizeof(SessionAttribute));
    if (tmpAttr == NULL) {
        TRANS_LOGE(TRANS_SDK, "SoftBusCalloc SessionAttribute failed");
        return NULL;
    }

    *isEncyptedRawStream = false;
    tmpAttr->fastTransData = NULL;
    tmpAttr->fastTransDataSize = 0;
    switch (info->dataType) {
        case DATA_TYPE_MESSAGE:
            tmpAttr->dataType = TYPE_MESSAGE;
            break;
        case DATA_TYPE_BYTES:
            tmpAttr->dataType = TYPE_BYTES;
            break;
        case DATA_TYPE_FILE:
            tmpAttr->dataType = TYPE_FILE;
            break;
        case DATA_TYPE_RAW_STREAM:
        case DATA_TYPE_RAW_STREAM_ENCRYPED:
            tmpAttr->dataType = TYPE_STREAM;
            tmpAttr->attr.streamAttr.streamType = RAW_STREAM;
            *isEncyptedRawStream = (info->dataType == DATA_TYPE_RAW_STREAM_ENCRYPED);
            break;
        case DATA_TYPE_VIDEO_STREAM:
            tmpAttr->dataType = TYPE_STREAM;
            tmpAttr->attr.streamAttr.streamType = COMMON_VIDEO_STREAM;
            break;
        case DATA_TYPE_AUDIO_STREAM:
            tmpAttr->dataType = TYPE_STREAM;
            tmpAttr->attr.streamAttr.streamType = COMMON_AUDIO_STREAM;
            break;
        case DATA_TYPE_SLICE_STREAM:
            tmpAttr->dataType = TYPE_STREAM;
            tmpAttr->attr.streamAttr.streamType = VIDEO_SLICE_STREAM;
            break;
        default:
            // The socket used for listening does not require setting the data type
            break;
    }
    return tmpAttr;
}

int32_t ClientAddSocket(const SocketInfo *info, int32_t *sessionId)
{
    if (info == NULL || sessionId == NULL) {
        TRANS_LOGE(TRANS_SDK, "ClientAddSocket invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    bool isEncyptedRawStream = false;
    SessionAttribute *tmpAttr = CreateSessionAttributeBySocketInfoTrans(info, &isEncyptedRawStream);
    if (tmpAttr == NULL) {
        TRANS_LOGE(TRANS_SDK, "Create SessionAttribute failed");
        return SOFTBUS_MALLOC_ERR;
    }

    SessionParam param = {
        .sessionName = info->name != NULL ? info->name : "",
        .peerSessionName = info->peerName != NULL ? info->peerName : "",
        .peerDeviceId = info->peerNetworkId != NULL ? info->peerNetworkId : "",
        .groupId = "reserved",
        .actionId = INVALID_ACTION_ID,
        .attr = tmpAttr,
    };

    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    int32_t ret = ClientAddSocketSession(&param, isEncyptedRawStream, sessionId, &isEnabled);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(tmpAttr);
        if (ret == SOFTBUS_TRANS_SESSION_REPEATED) {
            TRANS_LOGI(TRANS_SDK, "socket already create");
            return SOFTBUS_OK;
        }
        TRANS_LOGE(TRANS_SDK, "add socket err: ret=%{public}d", ret);
        return ret;
    }
    SoftBusFree(tmpAttr);
    return SOFTBUS_OK;
}

static bool IsValidSocketListener(const ISocketListener *listener, bool isListenSocket)
{
    if (listener == NULL || listener->OnShutdown == NULL) {
        TRANS_LOGE(TRANS_SDK, "listener is null or OnShutdown is null");
        return false;
    }

    if (isListenSocket && listener->OnBind == NULL) {
        TRANS_LOGE(TRANS_SDK, "no OnBind callback function of listen socket");
        return false;
    }

    return true;
}

static bool IsValidAsyncBindSocketListener(const ISocketListener *listener, bool isAsync)
{
    if (isAsync && (listener->OnBind == NULL)) {
        TRANS_LOGE(TRANS_SDK, "no OnBind callback function of async bind");
        return false;
    }
    if (isAsync && (listener->OnError == NULL)) {
        TRANS_LOGE(TRANS_SDK, "no onError callback function of async bind");
        return false;
    }
    return true;
}

static int32_t GetMaxIdleTimeout(const QosTV *qos, uint32_t qosCount, uint32_t *maxIdleTimeout)
{
#define TRANS_DEFAULT_MAX_IDLE_TIMEOUT 0
    int32_t tmpIdleTime = 0;
    int32_t ret = GetQosValue(qos, qosCount, QOS_TYPE_MAX_IDLE_TIMEOUT, &tmpIdleTime, TRANS_DEFAULT_MAX_IDLE_TIMEOUT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get maximum idle time failed, ret=%{public}d", ret);
        return ret;
    }

    if (tmpIdleTime < 0) {
        TRANS_LOGE(TRANS_SDK, "invalid maximum idle time, maxIdleTimeout=%{public}d", tmpIdleTime);
        return SOFTBUS_INVALID_PARAM;
    }

    *maxIdleTimeout = (uint32_t)tmpIdleTime;
    return SOFTBUS_OK;
}

static int32_t CheckSessionCancelState(int32_t socket)
{
    SocketLifecycleData lifecycle;
    (void)memset_s(&lifecycle, sizeof(SocketLifecycleData), 0, sizeof(SocketLifecycleData));
    int32_t ret = GetSocketLifecycleAndSessionNameBySessionId(socket, NULL, &lifecycle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get socket state failed, socket=%{public}d failed, ret=%{public}d", socket, ret);
        return ret;
    }
    if (lifecycle.sessionState == SESSION_STATE_CANCELLING) {
        TRANS_LOGW(TRANS_SDK, "This socket already in cancelling state. socket=%{public}d", socket);
        int32_t channelId = INVALID_CHANNEL_ID;
        int32_t type = CHANNEL_TYPE_BUTT;
        ret = ClientGetChannelBySessionId(socket, &channelId, &type, NULL);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get channel by socket=%{public}d failed, ret=%{public}d", socket, ret);
        }
        ret = ClientTransCloseChannel(channelId, type);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "close channel err: ret=%{public}d, channelId=%{public}d, channeType=%{public}d", ret,
                channelId, type);
        }
        return lifecycle.bindErrCode;
    }
    return SOFTBUS_OK;
}

int32_t ClientBind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener, bool isAsync)
{
    if (!IsValidSessionId(socket) || !IsValidSocketListener(listener, false) ||
        !IsValidAsyncBindSocketListener(listener, isAsync) || !IsValidQosInfo(qos, qosCount)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    // For rebind, clear the socket state.
    int32_t ret = ClientSetSocketState(socket, 0, SESSION_ROLE_INIT);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "init session role failed, ret=%{public}d", ret);
    ret = SetSessionStateBySessionId(socket, SESSION_STATE_INIT, 0);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "init session state failed, ret=%{public}d", ret);

    ret = ClientSetListenerBySessionId(socket, listener, false);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "set listener by socket=%{public}d failed, ret=%{public}d", socket, ret);

    uint32_t maxIdleTimeout = 0;
    ret = GetMaxIdleTimeout(qos, qosCount, &maxIdleTimeout);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "get maximum idle time failed, ret=%{public}d", ret);

    ret = SetSessionIsAsyncById(socket, isAsync);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "set session is async failed, ret=%{public}d", ret);

    TransInfo transInfo;
    ret = ClientIpcOpenSession(socket, qos, qosCount, &transInfo, isAsync);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "open session failed, ret=%{public}d", ret);

    if (!isAsync) {
        ret = CheckSessionCancelState(socket);
        TRANS_CHECK_AND_RETURN_RET_LOGE(
            ret == SOFTBUS_OK, ret, TRANS_SDK, "check session cancel state failed, ret=%{public}d", ret);
        ret = ClientWaitSyncBind(socket);
        TRANS_CHECK_AND_RETURN_RET_LOGE(
            ret == SOFTBUS_OK, ret, TRANS_SDK, "ClientWaitSyncBind err, ret=%{public}d", ret);
        (void)SetSessionStateBySessionId(socket, SESSION_STATE_CALLBACK_FINISHED, 0);
    }
    ret = ClientSetSocketState(socket, maxIdleTimeout, SESSION_ROLE_CLIENT);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "set session role failed, ret=%{public}d", ret);

    if (!isAsync) {
        (void)ClientGetChannelBySessionId(socket, &(transInfo.channelId), &(transInfo.channelType), NULL);
        TRANS_LOGI(TRANS_SDK, "Bind ok: socket=%{public}d, channelId=%{public}d, channelType=%{public}d", socket,
            transInfo.channelId, transInfo.channelType);
    } else {
        TRANS_LOGI(TRANS_SDK, "Bind async ok: socket=%{public}d", socket);
    }
    return SOFTBUS_OK;
}

int32_t ClientListen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    if (!IsValidSocketListener(listener, true) || !IsValidQosInfo(qos, qosCount)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = ClientSetListenerBySessionId(socket, listener, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set listener by socket=%{public}d failed. ret=%{public}d", socket, ret);
        return ret;
    }

    uint32_t maxIdleTimeout = 0;
    ret = GetMaxIdleTimeout(qos, qosCount, &maxIdleTimeout);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get maximum idle time failed, ret=%{public}d", ret);
        return ret;
    }

    ret = ClientSetSocketState(socket, maxIdleTimeout, SESSION_ROLE_SERVER);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set session role failed. ret=%{public}d", ret);
        return ret;
    }

    TRANS_LOGD(TRANS_SDK, "Listen ok: socket=%{public}d", socket);
    return SOFTBUS_OK;
}

void ClientShutdown(int32_t socket, int32_t cancelReason)
{
    if (!IsValidSessionId(socket)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return;
    }

    SocketLifecycleData lifecycle;
    (void)memset_s(&lifecycle, sizeof(SocketLifecycleData), 0, sizeof(SocketLifecycleData));
    char sessioName[SESSION_NAME_SIZE_MAX] = { 0 };
    int32_t ret = GetSocketLifecycleAndSessionNameBySessionId(socket, sessioName, &lifecycle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get socket state failed, socket=%{public}d failed, ret=%{public}d", socket, ret);
        return;
    }
    if (lifecycle.sessionState == SESSION_STATE_CANCELLING) {
        TRANS_LOGW(TRANS_SDK, "This socket already in cancelling state. socket=%{public}d", socket);
    }
    SetSessionStateBySessionId(socket, SESSION_STATE_CANCELLING, cancelReason);
    if (lifecycle.sessionState == SESSION_STATE_INIT) {
        TRANS_LOGI(TRANS_SDK, "This socket state is init, socket=%{public}d", socket);
    } else if (lifecycle.sessionState == SESSION_STATE_OPENING) {
        TRANS_LOGI(TRANS_SDK, "This socket state is opening, socket=%{public}d", socket);
        int32_t ret = ServerIpcCloseChannel(sessioName, socket, CHANNEL_TYPE_UNDEFINED);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "Call sa delete socket failed: ret=%{public}d", ret);
        }
        ret = ClientSignalSyncBind(socket, 0);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "sync signal bind failed, ret=%{public}d, socket=%{public}d", ret, socket);
        }
    } else if (lifecycle.sessionState == SESSION_STATE_OPENED ||
        lifecycle.sessionState == SESSION_STATE_CALLBACK_FINISHED) {
        if (lifecycle.sessionState == SESSION_STATE_OPENED) {
            TRANS_LOGI(TRANS_SDK, "This socket state is opened, socket=%{public}d", socket);
            CheckSessionIsOpened(socket, true);
        }
        TRANS_LOGI(TRANS_SDK, "This socket state is callback finish, socket=%{public}d", socket);
        int32_t channelId = INVALID_CHANNEL_ID;
        int32_t type = CHANNEL_TYPE_BUTT;
        ret = ClientGetChannelBySessionId(socket, &channelId, &type, NULL);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get channel by socket=%{public}d failed, ret=%{public}d", socket, ret);
        } else {
            AddSessionStateClosing();
        }
        ret = ClientTransCloseChannel(channelId, type);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "close channel err: ret=%{public}d, channelId=%{public}d, channeType=%{public}d", ret,
                channelId, type);
        }
        if (lifecycle.sessionState == SESSION_STATE_OPENED) {
            (void)ClientSignalSyncBind(socket, cancelReason);
        }
    }
    if (cancelReason == SOFTBUS_TRANS_STOP_BIND_BY_TIMEOUT) {
        SetSessionInitInfoById(socket);
        TRANS_LOGI(TRANS_SDK, "Bind timeout Shutdown ok, no delete socket: socket=%{public}d", socket);
        return;
    }
    (void)ClientDeleteSocketSession(socket);

    TRANS_LOGI(TRANS_SDK, "Shutdown ok: socket=%{public}d", socket);
}

int32_t GetSocketMtuSize(int32_t socket, uint32_t *mtuSize)
{
    if (!IsValidSessionId(socket) || mtuSize == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    SessionEnableStatus enableStatus = ENABLE_STATUS_INIT;
    int32_t ret = ClientGetChannelBySessionId(socket, &channelId, &type, &enableStatus);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channel by socket=%{public}d failed, ret=%{public}d.", socket, ret);
        return ret;
    }

    if (enableStatus != ENABLE_STATUS_SUCCESS) {
        TRANS_LOGI(TRANS_SDK, "socket not enable");
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }

    uint32_t dataConfig = INVALID_DATA_CONFIG;
    if (ClientGetDataConfigByChannelId(channelId, type, &dataConfig) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get config by channelId=%{public}d failed", channelId);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }

    *mtuSize = dataConfig;
    TRANS_LOGI(TRANS_SDK, "get mtuSize success, socket=%{public}d, mtu=%{public}" PRIu32, socket, *mtuSize);
    return SOFTBUS_OK;
}

int32_t ClientDfsBind(int32_t socket, const ISocketListener *listener)
{
    if (!IsValidSessionId(socket) || !IsValidSocketListener(listener, false)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = ClientSetListenerBySessionId(socket, listener, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set listener by socket=%{public}d failed, ret=%{public}d", socket, ret);
        return ret;
    }

    ret = SetSessionIsAsyncById(socket, false);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "set session is async failed, ret=%{public}d", ret);
    TransInfo transInfo;
    ret = ClientDfsIpcOpenSession(socket, &transInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "open session failed, ret=%{public}d", ret);
        return ret;
    }

    ret = ClientSetChannelBySessionId(socket, &transInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "set channel by socket=%{public}d failed, ret=%{public}d", socket, ret);
    ret = SetSessionStateBySessionId(socket, SESSION_STATE_OPENED, 0);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "set session state failed socket=%{public}d, ret=%{public}d", socket, ret);
    ret = ClientWaitSyncBind(socket);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "ClientWaitSyncBind err, ret=%{public}d", ret);

    ret = ClientSetSocketState(socket, 0, SESSION_ROLE_CLIENT);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "set session role failed, ret=%{public}d", ret);
    TRANS_LOGI(TRANS_SDK, "DfsBind ok: socket=%{public}d, channelId=%{public}d, channelType=%{public}d", socket,
        transInfo.channelId, transInfo.channelType);
    return SOFTBUS_OK;
}
