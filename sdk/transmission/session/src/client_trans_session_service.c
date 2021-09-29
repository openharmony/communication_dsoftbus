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

#include "client_trans_session_service.h"

#include <unistd.h>

#include "client_trans_channel_manager.h"
#include "client_trans_file_listener.h"
#include "client_trans_session_manager.h"
#include "inner_session.h"
#include "securec.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_trans_def.h"
#include "softbus_utils.h"
#include "trans_server_proxy.h"

static bool IsValidSessionId(int sessionId)
{
    if ((sessionId <= 0) || (sessionId > MAX_SESSION_ID)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid sessionId [%d]", sessionId);
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid ISessionListener");
    return false;
}

static int32_t OpenSessionWithExistSession(int32_t sessionId, bool isEnabled)
{
    if (!isEnabled) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "the channel is opening");
        return sessionId;
    }

    ISessionListener listener = {0};
    if (ClientGetSessionCallbackById(sessionId, &listener) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get session listener failed");
        return sessionId;
    }

    if (listener.OnSessionOpened(sessionId, SOFTBUS_OK) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "session callback OnSessionOpened failed");
        CloseSession(sessionId);
        return INVALID_SESSION_ID;
    }
    return sessionId;
}

int CreateSessionServer(const char *pkgName, const char *sessionName, const ISessionListener *listener)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidListener(listener)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateSessionServer invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "CreateSessionServer: pkgName=%s, sessionName=%s",
        pkgName, sessionName);

    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init softbus err");
        return SOFTBUS_ERR;
    }

    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid pkg name");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret = ClientAddSessionServer(SEC_TYPE_CIPHERTEXT, pkgName, sessionName, listener);
    if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SessionServer is already created in client");
        ret = SOFTBUS_OK;
    } else if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add session server err");
        return ret;
    }

    ret = ServerIpcCreateSessionServer(pkgName, sessionName);
    if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SessionServer is already created in server");
        ret = SOFTBUS_OK;
    } else if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Server createSessionServer failed");
        (void)ClientDeleteSessionServer(SEC_TYPE_CIPHERTEXT, sessionName);
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "CreateSessionServer ok: ret=%d", ret);
    return ret;
}

int RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemoveSessionServer invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "RemoveSessionServer: pkgName=%s, sessionName=%s",
        pkgName, sessionName);

    int32_t ret = ServerIpcRemoveSessionServer(pkgName, sessionName);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remove in server failed");
        return ret;
    }

    ret = ClientDeleteSessionServer(SEC_TYPE_CIPHERTEXT, sessionName);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "delete session server [%s] failed", sessionName);
    }
    DeleteFileListener(sessionName);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "RemoveSessionServer ok: ret=%d", ret);
    return ret;
}

static int32_t CheckParamIsValid(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, const SessionAttribute *attr)
{
    if (!IsValidString(mySessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerSessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerDeviceId, DEVICE_ID_SIZE_MAX) ||
        (attr == NULL) ||
        (attr->dataType >= TYPE_BUTT)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (groupId == NULL || strlen(groupId) >= GROUP_ID_SIZE_MAX) {
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

int OpenSession(const char *mySessionName, const char *peerSessionName, const char *peerDeviceId,
    const char *groupId, const SessionAttribute *attr)
{
    int ret = CheckParamIsValid(mySessionName, peerSessionName, peerDeviceId, groupId, attr);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession invalid param");
        return INVALID_SESSION_ID;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenSession: mySessionName=%s, peerSessionName=%s",
        mySessionName, peerSessionName);

    TransInfo transInfo;
    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerDeviceId,
        .groupId = groupId,
        .attr = attr,
    };

    int32_t sessionId = INVALID_SESSION_ID;
    bool isEnabled = false;

    ret = ClientAddSession(&param, &sessionId, &isEnabled);
    if (ret != SOFTBUS_OK) {
        if (ret == SOFTBUS_TRANS_SESSION_REPEATED) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session already opened");
            return OpenSessionWithExistSession(sessionId, isEnabled);
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add session err: ret=%d", ret);
        return ret;
    }

    ret = ServerIpcOpenSession(&param, &transInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open session ipc err: ret=%d", ret);
        (void)ClientDeleteSession(sessionId);
        return ret;
    }

    ret = ClientSetChannelBySessionId(sessionId, &transInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open session failed");
        (void)ClientDeleteSession(sessionId);
        return INVALID_SESSION_ID;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenSession ok: sessionId=%d, channelId=%d, channelType = %d",
        sessionId, transInfo.channelId, transInfo.channelType);
    return sessionId;
}

static int32_t ConvertAddrStr(const char *addrStr, ConnectionAddr *addrInfo)
{
    if (addrStr == NULL || addrInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    cJSON *obj = cJSON_Parse(addrStr);
    if (obj == NULL) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (memset_s(addrInfo, sizeof(ConnectionAddr), 0x0, sizeof(ConnectionAddr)) != EOK) {
        cJSON_Delete(obj);
        return SOFTBUS_MEM_ERR;
    }
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
        cJSON_Delete(obj);
        addrInfo->type = CONNECTION_ADDR_BLE;
        return SOFTBUS_OK;
    }
    cJSON_Delete(obj);
    return SOFTBUS_ERR;
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
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TransInfo transInfo;
    int32_t addrIndex = IsValidAddrInfoArr(addrInfo, num);
    ConnectionAddr *addr = NULL;
    ConnectionAddr mix;
    if (addrIndex < 0) {
        if (ConvertAddrStr(mixAddr, &mix) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid addrInfo param");
            return SOFTBUS_INVALID_PARAM;
        }
        addr = &mix;
    } else {
        addr = (ConnectionAddr *)&addrInfo[addrIndex];
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenAuthSession: mySessionName=%s", sessionName);

    int32_t sessionId;
    int32_t ret = ClientAddAuthSession(sessionName, &sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add non encrypt session err: ret=%d", ret);
        return ret;
    }

    transInfo.channelId = ServerIpcOpenAuthSession(sessionName, addr);
    transInfo.channelType = CHANNEL_TYPE_AUTH;
    ret = ClientSetChannelBySessionId(sessionId, &transInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenAuthSession failed");
        (void)ClientDeleteSession(sessionId);
        return INVALID_SESSION_ID;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenAuthSession ok: sessionId=%d, channelId=%d, channelType = %d",
        sessionId, transInfo.channelId, transInfo.channelType);
    return sessionId;
}

void NotifyAuthSuccess(int sessionId)
{
    int32_t channelId;
    int32_t type;
    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &type, NULL);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get channel err");
        return;
    }
    if (ServerIpcNotifyAuthSuccess(channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcNotifyAuthSuccess err");
        return;
    }
}

static void CheckSessionIsOpened(int32_t sessionId)
{
#define SESSION_STATUS_CHECK_MAX_NUM 100
#define SESSION_CHECK_PERIOD 50000
    int32_t i = 0;
    bool isEnable = false;

    while (i < SESSION_STATUS_CHECK_MAX_NUM) {
        if (ClientGetChannelBySessionId(sessionId, NULL, NULL, &isEnable) != SOFTBUS_OK) {
            return;
        }
        if (isEnable == true) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "CheckSessionIsOpened session is enable");
            return;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CheckSessionIsOpened session is opening, i=%d", i);
        usleep(SESSION_CHECK_PERIOD);
        i++;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CheckSessionIsOpened session open timeout");
    return;
}

int OpenSessionSync(const char *mySessionName, const char *peerSessionName, const char *peerDeviceId,
    const char *groupId, const SessionAttribute *attr)
{
    int ret = CheckParamIsValid(mySessionName, peerSessionName, peerDeviceId, groupId, attr);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSessionSync invalid param");
        return INVALID_SESSION_ID;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenSessionSync: mySessionName=%s, peerSessionName=%s",
        mySessionName, peerSessionName);

    TransInfo transInfo;
    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerDeviceId,
        .groupId = groupId,
        .attr = attr,
    };

    int32_t sessionId = INVALID_SESSION_ID;
    bool isEnabled = false;

    ret = ClientAddSession(&param, &sessionId, &isEnabled);
    if (ret != SOFTBUS_OK) {
        if (ret == SOFTBUS_TRANS_SESSION_REPEATED) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session already opened");
            CheckSessionIsOpened(sessionId);
            return OpenSessionWithExistSession(sessionId, isEnabled);
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add session err: ret=%d", ret);
        return ret;
    }

    ret = ServerIpcOpenSession(&param, &transInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open session ipc err: ret=%d", ret);
        (void)ClientDeleteSession(sessionId);
        return ret;
    }
    ret = ClientSetChannelBySessionId(sessionId, &transInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server open session err: ret=%d", ret);
        (void)ClientDeleteSession(sessionId);
        return INVALID_SESSION_ID;
    }

    CheckSessionIsOpened(sessionId);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenSessionSync ok: sessionId=%d, channelId=%d",
        sessionId, transInfo.channelId);
    return sessionId;
}

void CloseSession(int sessionId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "CloseSession: sessionId=%d", sessionId);
    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    int32_t ret;

    if (!IsValidSessionId(sessionId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return;
    }
    ret = ClientGetChannelBySessionId(sessionId, &channelId, &type, NULL);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get channel err");
        return;
    }
    ret = ClientTransCloseChannel(channelId, type);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "close channel err: ret=%d, channelId=%d, channeType=%d",
            ret, channelId, type);
    }

    ret = ClientDeleteSession(sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CloseSession delete session err");
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "CloseSession ok");
    return;
}

int GetMySessionName(int sessionId, char *sessionName, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (sessionName == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }

    return ClientGetSessionDataById(sessionId, sessionName, len, KEY_SESSION_NAME);
}

int GetPeerSessionName(int sessionId, char *sessionName, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (sessionName == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }

    return ClientGetSessionDataById(sessionId, sessionName, len, KEY_PEER_SESSION_NAME);
}

int GetPeerDeviceId(int sessionId, char *devId, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (devId == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }

    return ClientGetSessionDataById(sessionId, devId, len, KEY_PEER_DEVICE_ID);
}

int GetSessionSide(int sessionId)
{
    return ClientGetSessionSide(sessionId);
}

int SetFileReceiveListener(const char *pkgName, const char *sessionName,
    const IFileReceiveListener *recvListener, const char *rootDir)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(rootDir, FILE_RECV_ROOT_DIR_SIZE_MAX) || recvListener == NULL) {
        LOG_ERR("set file receive listener invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("set file receive listener init softbus client error");
        return SOFTBUS_ERR;
    }
    return TransSetFileReceiveListener(sessionName, recvListener, rootDir);
}

int SetFileSendListener(const char *pkgName, const char *sessionName, const IFileSendListener *sendListener)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX) ||
        sendListener == NULL) {
        LOG_ERR("set file send listener invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("set file send listener init softbus client error");
        return SOFTBUS_ERR;
    }
    return TransSetFileSendListener(sessionName, sendListener);
}
