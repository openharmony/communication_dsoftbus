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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>

#include "client_qos_manager.h"
#include "client_trans_channel_manager.h"
#include "client_trans_file_listener.h"
#include "client_trans_session_manager.h"
#include "dfs_session.h"
#include "inner_session.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_trans_def.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"
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
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1) ||
        !IsValidListener(listener)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateSessionServer invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyOut = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "CreateSessionServer: pkgName=%s, sessionName=%s",
        pkgName, AnonyDevId(&anonyOut, sessionName));
    SoftBusFree(anonyOut);

    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init softbus err");
        return SOFTBUS_TRANS_SESSION_ADDPKG_FAILED;
    }

    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid pkg name");
        return SOFTBUS_INVALID_PKGNAME;
    }

    int ret = ClientAddSessionServer(SEC_TYPE_CIPHERTEXT, pkgName, sessionName, listener);
    if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SessionServer is already created in client");
    } else if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add session server err, ret=%d.", ret);
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
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemoveSessionServer invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyOut = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "RemoveSessionServer: pkgName=%s, sessionName=%s",
        pkgName, AnonyDevId(&anonyOut, sessionName));
    SoftBusFree(anonyOut);

    int32_t ret = ServerIpcRemoveSessionServer(pkgName, sessionName);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remove in server failed, ret=%d.", ret);
        return ret;
    }

    ret = ClientDeleteSessionServer(SEC_TYPE_CIPHERTEXT, sessionName);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "delete session server[%s] failed, ret=%d.", sessionName, ret);
        DeleteFileListener(sessionName);
        return ret;
    }
    DeleteFileListener(sessionName);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "RemoveSessionServer ok: ret=%d", ret);
    return ret;
}

static int32_t CheckParamIsValid(const char *mySessionName, const char *peerSessionName,
    const char *peerNetworkId, const char *groupId, const SessionAttribute *attr)
{
    if (!IsValidString(mySessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerSessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerNetworkId, DEVICE_ID_SIZE_MAX) ||
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

int OpenSession(const char *mySessionName, const char *peerSessionName, const char *peerNetworkId,
    const char *groupId, const SessionAttribute *attr)
{
    int ret = CheckParamIsValid(mySessionName, peerSessionName, peerNetworkId, groupId, attr);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession invalid param, ret=%d.", ret);
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyOutMy = NULL;
    char *anonyOutPeer = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenSession: mySessionName=%s, peerSessionName=%s",
        AnonyDevId(&anonyOutMy, mySessionName), AnonyDevId(&anonyOutPeer, peerSessionName));
    SoftBusFree(anonyOutMy);
    SoftBusFree(anonyOutPeer);

    TransInfo transInfo;
    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerNetworkId,
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
    int port;
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
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
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
    char *anonyOut = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenAuthSession: mySessionName=%s",
        AnonyDevId(&anonyOut, sessionName));
    SoftBusFree(anonyOut);

    int32_t sessionId;
    int32_t ret = ClientAddAuthSession(sessionName, &sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add non encrypt session err: ret=%d", ret);
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
    int32_t channelId = -1;
    int32_t channelType = -1;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "NotifyAuthSuccess sessionId:%d", sessionId);
    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &channelType, NULL);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get session=%d channel err, ret:%d.", sessionId, ret);
        return;
    }

    int isServer = 0;
    if (ClientGetSessionIntegerDataById(sessionId, &isServer, KEY_IS_SERVER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get isServer failed");
        return;
    }
    if (isServer) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "device is service side, no notification");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "device is client side");

    if (ServerIpcNotifyAuthSuccess(channelId, channelType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "channel=%d type=%d ServerIpcNotifyAuthSuccess err", channelId, channelType);
        return;
    }
}

static int32_t CheckSessionIsOpened(int32_t sessionId)
{
#define SESSION_STATUS_CHECK_MAX_NUM 100
#define SESSION_CHECK_PERIOD 50000
    int32_t i = 0;
    bool isEnable = false;

    while (i < SESSION_STATUS_CHECK_MAX_NUM) {
        if (ClientGetChannelBySessionId(sessionId, NULL, NULL, &isEnable) != SOFTBUS_OK) {
            return SOFTBUS_NOT_FIND;
        }
        if (isEnable == true) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "CheckSessionIsOpened session is enable");
            return SOFTBUS_OK;
        }
        usleep(SESSION_CHECK_PERIOD);
        i++;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CheckSessionIsOpened session open timeout");
    return SOFTBUS_ERR;
}

static void OpenSessionSyncOutSessionName(const char *mySessionName, const char *peerSessionName)
{
    char *anonyOutMy = NULL;
    char *anonyOutPeer = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenSessionSync: mySessionName=%s, peerSessionName=%s",
        AnonyDevId(&anonyOutMy, mySessionName), AnonyDevId(&anonyOutPeer, peerSessionName));
    SoftBusFree(anonyOutMy);
    SoftBusFree(anonyOutPeer);
}

int OpenSessionSync(const char *mySessionName, const char *peerSessionName, const char *peerNetworkId,
    const char *groupId, const SessionAttribute *attr)
{
    int ret = CheckParamIsValid(mySessionName, peerSessionName, peerNetworkId, groupId, attr);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSessionSync invalid param");
        return INVALID_SESSION_ID;
    }
    OpenSessionSyncOutSessionName(mySessionName, peerSessionName);

    TransInfo transInfo;
    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerNetworkId,
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
        return SOFTBUS_TRANS_SESSION_SET_CHANNEL_FAILED;
    }

    ret = CheckSessionIsOpened(sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CheckSessionIsOpened err: ret=%d", ret);
        (void)ClientDeleteSession(sessionId);
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
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

int GetPeerDeviceId(int sessionId, char *networkId, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (networkId  == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }

    return ClientGetSessionDataById(sessionId, networkId, len, KEY_PEER_DEVICE_ID);
}

int GetSessionSide(int sessionId)
{
    return ClientGetSessionSide(sessionId);
}

static bool IsValidFileReceivePath(const char *rootDir)
{
    if (!IsValidString(rootDir, FILE_RECV_ROOT_DIR_SIZE_MAX)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "receive path[%s] invalid.", rootDir);
        return false;
    }
    char *absPath = realpath(rootDir, NULL);
    if (absPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "receive path[%s] not exist,[%d].", rootDir, errno);
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set file receive listener invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set file receive listener init softbus client error");
        return SOFTBUS_TRANS_SESSION_ADDPKG_FAILED;
    }
    return TransSetFileReceiveListener(sessionName, recvListener, rootDir);
}

int SetFileSendListener(const char *pkgName, const char *sessionName, const IFileSendListener *sendListener)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1) ||
        sendListener == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set file send listener invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set file send listener init softbus client error");
        return SOFTBUS_TRANS_SESSION_ADDPKG_FAILED;
    }
    return TransSetFileSendListener(sessionName, sendListener);
}

static const char *g_busName = "DistributedFileService";

static int32_t IsValidDFSSession(int32_t sessionId, int32_t *channelId)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    int32_t type;
    if (GetMySessionName(sessionId, sessionName, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get dfs session name failed");
        return SOFTBUS_ERR;
    }
    if (strncmp(sessionName, g_busName, strlen(g_busName)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid dfs session name");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }

    if (ClientGetChannelBySessionId(sessionId, channelId, &type, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get channel failed");
        return SOFTBUS_ERR;
    }
    if (type != CHANNEL_TYPE_TCP_DIRECT) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid channel type");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }
    return SOFTBUS_OK;
}

int32_t GetSessionKey(int32_t sessionId, char *key, unsigned int len)
{
    int32_t channelId;
    if (!IsValidSessionId(sessionId) || key == NULL || len < SESSION_KEY_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsValidDFSSession(sessionId, &channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid dfs session");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }
    return ClientGetSessionKey(channelId, key, len);
}

int32_t GetSessionHandle(int32_t sessionId, int *handle)
{
    int32_t channelId;
    if (!IsValidSessionId(sessionId) || handle == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsValidDFSSession(sessionId, &channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid dfs session");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }
    return ClientGetHandle(channelId, handle);
}

int32_t DisableSessionListener(int32_t sessionId)
{
    int32_t channelId;
    if (!IsValidSessionId(sessionId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsValidDFSSession(sessionId, &channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid dfs session");
        return SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    }
    return ClientDisableSessionListener(channelId);
}

int32_t QosReport(int32_t sessionId, int32_t appType, int32_t quality)
{
    if (quality != QOS_IMPROVE && quality != QOS_RECOVER) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "qos report invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &type, NULL);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get channel err, ret=%d.", ret);
        return ret;
    }
    if (ClientGetSessionSide(sessionId) != IS_CLIENT) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "qos report sessionId[%d] not exist or not client side", sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if ((ret = ClientQosReport(channelId, type, appType, quality)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "qos report sessionId[%d] failed", sessionId);
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

int32_t FindConfigType(int32_t channelType, int32_t businessType)
{
    for (uint32_t i = 0; i < sizeof(g_configTypeMap) / sizeof(ConfigTypeMap); i++) {
        if ((g_configTypeMap[i].channelType == channelType) &&
            (g_configTypeMap[i].businessType == businessType)) {
            return g_configTypeMap[i].configType;
        }
    }
    return SOFTBUS_CONFIG_TYPE_MAX;
}

int ReadMaxSendBytesSize(int32_t channelId, int32_t type, void* value, uint32_t valueSize)
{
    (void)channelId;
    if (valueSize != sizeof(uint32_t)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "value size is %d, not match", valueSize);
        return SOFTBUS_INVALID_PARAM;
    }

    ConfigType configType = (ConfigType)FindConfigType(type, BUSINESS_TYPE_BYTE);
    if (configType == SOFTBUS_CONFIG_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid channelType: %d, businessType: %d",
            type, BUSINESS_TYPE_BYTE);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get config failed, configType: %d.", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }

    (*(uint32_t*)value) = maxLen;
    return SOFTBUS_OK;
}

int ReadMaxSendMessageSize(int32_t channelId, int32_t type, void* value, uint32_t valueSize)
{
    (void)channelId;
    if (valueSize != sizeof(uint32_t)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "value size is %d, not match", valueSize);
        return SOFTBUS_INVALID_PARAM;
    }

    ConfigType configType = (ConfigType)FindConfigType(type, BUSINESS_TYPE_MESSAGE);
    if (configType == SOFTBUS_CONFIG_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid channelType: %d, businessType: %d",
            type, BUSINESS_TYPE_MESSAGE);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get config failed, configType: %d.", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }

    (*(uint32_t*)value) = maxLen;
    return SOFTBUS_OK;
}


static const SessionOptionItem g_SessionOptionArr[SESSION_OPTION_BUTT] = {
    {true, ReadMaxSendBytesSize},
    {true, ReadMaxSendMessageSize},
};

int GetSessionOption(int sessionId, SessionOption option, void* optionValue, uint32_t valueSize)
{
    if ((option >= SESSION_OPTION_BUTT) || (optionValue == NULL) || (valueSize == 0)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetSessionOption invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_SessionOptionArr[option].canRead) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "option %d can not be get", option);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &type, NULL);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get channel err, ret=%d.", ret);
        return ret;
    }

    return g_SessionOptionArr[option].readFunc(channelId, type, optionValue, valueSize);
}
