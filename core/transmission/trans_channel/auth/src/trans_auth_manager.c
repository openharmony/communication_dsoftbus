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

#include "trans_auth_manager.h"

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_net_builder.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_auth_message.h"
#include "trans_session_manager.h"

#define AUTH_CHANNEL_REQ 0
#define AUTH_CHANNEL_REPLY 1

#define AUTH_GROUP_ID "auth group id"
#define AUTH_SESSION_KEY "auth session key"

typedef struct {
    ListNode node;
    AppInfo appInfo;
    int64_t authId;
    ConnectOption connOpt;
    bool isConnOptValid;
} AuthChannelInfo;

static SoftBusList *g_authChannelList = NULL;
static int32_t g_channelId = 0;
static IServerChannelCallBack *g_cb = NULL;

static void TransPostAuthChannelErrMsg(int64_t authId, int32_t errcode, const char *errMsg);
static int32_t TransPostAuthChannelMsg(const AppInfo *appInfo, int64_t authId, int32_t flag);
static AuthChannelInfo *CreateAuthChannelInfo(const char *sessionName);
static int32_t AddAuthChannelInfo(AuthChannelInfo *info);
static void DelAuthChannelInfoByChanId(int32_t channelId);
static void DelAuthChannelInfoByAuthId(int64_t authId);

static int32_t GenerateAuthChannelId()
{
    g_channelId++;
    return g_channelId;
}

static int32_t GetAuthChannelInfoByChanId(int32_t channelId, AuthChannelInfo *dstInfo)
{
    if (dstInfo == NULL || g_authChannelList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&g_authChannelList->lock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_authChannelList->list, AuthChannelInfo, node) {
        if (info->appInfo.myData.channelId == channelId) {
            if (memcpy_s(dstInfo, sizeof(AuthChannelInfo), info, sizeof(AuthChannelInfo)) != EOK) {
                (void)pthread_mutex_unlock(&g_authChannelList->lock);
                return SOFTBUS_MEM_ERR;
            }
            (void)pthread_mutex_unlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    pthread_mutex_unlock(&g_authChannelList->lock);
    return SOFTBUS_ERR;
}

static int64_t GetAuthIdByChannelId(int32_t channelId)
{
    if (g_authChannelList == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_authChannelList->lock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    int64_t authId = -1;
    AuthChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_authChannelList->list, AuthChannelInfo, node) {
        if (info->appInfo.myData.channelId == channelId) {
            authId = info->authId;
            (void)pthread_mutex_unlock(&g_authChannelList->lock);
            return authId;
        }
    }
    pthread_mutex_unlock(&g_authChannelList->lock);
    return authId;
}

static int32_t GetChannelInfoByAuthId(int64_t authId, AuthChannelInfo *dstInfo)
{
    if (dstInfo == NULL || g_authChannelList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&g_authChannelList->lock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_authChannelList->list, AuthChannelInfo, node) {
        if (info->authId == authId) {
            if (memcpy_s(dstInfo, sizeof(AuthChannelInfo), info, sizeof(AuthChannelInfo)) != EOK) {
                (void)pthread_mutex_unlock(&g_authChannelList->lock);
                return SOFTBUS_MEM_ERR;
            }
            (void)pthread_mutex_unlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    pthread_mutex_unlock(&g_authChannelList->lock);
    return SOFTBUS_ERR;
}

static int32_t NotifyOpenAuthChannelSuccess(const AppInfo *appInfo, bool isServer)
{
    ChannelInfo channelInfo = {0};
    channelInfo.channelType = CHANNEL_TYPE_AUTH;
    channelInfo.isServer = isServer;
    channelInfo.isEnabled = true;
    channelInfo.channelId = appInfo->myData.channelId;
    channelInfo.peerDeviceId = (char *)appInfo->peerData.deviceId;
    channelInfo.peerSessionName = (char *)appInfo->peerData.sessionName;
    channelInfo.groupId = AUTH_GROUP_ID;
    channelInfo.sessionKey = AUTH_SESSION_KEY;
    channelInfo.keyLen = strlen(channelInfo.sessionKey) + 1;
    return g_cb->OnChannelOpened(appInfo->myData.pkgName, appInfo->myData.sessionName, &channelInfo);
}

static int32_t NotifyOpenAuthChannelFailed(const char *pkgName, int32_t channelId)
{
    return g_cb->OnChannelOpenFailed(pkgName, channelId, CHANNEL_TYPE_AUTH);
}

static int32_t NofifyCloseAuthChannel(const char *pkgName, int32_t channelId)
{
    return g_cb->OnChannelClosed(pkgName, channelId, CHANNEL_TYPE_AUTH);
}

static int32_t NotifyOnDataReceived(int64_t authId, const ConnectOption *option, const AuthTransDataInfo *info)
{
    AuthChannelInfo channel;
    if (GetChannelInfoByAuthId(authId, &channel) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return g_cb->OnDataReceived(channel.appInfo.myData.pkgName, channel.appInfo.myData.channelId, CHANNEL_TYPE_AUTH,
                                info->data, info->len, TRANS_SESSION_BYTES);
}

static int32_t CopyPeerAppInfo(AppInfo *recvAppInfo, AppInfo *channelAppInfo)
{
    if (recvAppInfo == NULL || channelAppInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(channelAppInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX,
            recvAppInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX) != EOK ||
        memcpy_s(recvAppInfo->myData.deviceId, DEVICE_ID_SIZE_MAX,
            channelAppInfo->myData.deviceId, DEVICE_ID_SIZE_MAX) != EOK ||
        memcpy_s(channelAppInfo->peerData.pkgName, PKG_NAME_SIZE_MAX,
            recvAppInfo->peerData.pkgName, PKG_NAME_SIZE_MAX) != EOK ||
        memcpy_s(recvAppInfo->myData.pkgName, PKG_NAME_SIZE_MAX,
            channelAppInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != EOK ||
        memcpy_s(channelAppInfo->peerData.sessionName, SESSION_NAME_SIZE_MAX, 
            recvAppInfo->peerData.sessionName, SESSION_NAME_SIZE_MAX) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OnRequsetUpdateAuthChannel(int64_t authId, AppInfo *appInfo)
{
    if (appInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    AuthChannelInfo *item = NULL;
    if (pthread_mutex_lock(&g_authChannelList->lock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    bool exists = false;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->authId == authId) {
            exists = true;
            break;
        }
    }
    if (!exists) {
        item = CreateAuthChannelInfo(appInfo->myData.sessionName);
        if (item == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateAuthChannelInfo failed");
            pthread_mutex_unlock(&g_authChannelList->lock);
            return SOFTBUS_ERR;
        }
        item->authId = authId;
        appInfo->myData.channelId = item->appInfo.myData.channelId;
        item->isConnOptValid = false;
        if (AddAuthChannelInfo(item) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "AddAuthChannelInfo failed");
            SoftBusFree(item);
            pthread_mutex_unlock(&g_authChannelList->lock);
            return SOFTBUS_ERR;
        } 
    }
    if (CopyPeerAppInfo(appInfo, &item->appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CopyPeerAppInfo failed");
        SoftBusFree(item);
        pthread_mutex_unlock(&g_authChannelList->lock);
        return SOFTBUS_MEM_ERR;
    }
    pthread_mutex_unlock(&g_authChannelList->lock);
    return SOFTBUS_OK;
} 


static void OnRecvAuthChannelRequest(int64_t authId, const char *data, int32_t len)
{
    if (data == NULL || len <= 0) {
        return;
    }

    AppInfo appInfo;
    int32_t ret = TransAuthChannelMsgUnpack(data, &appInfo); 
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpackRequest failed");
        TransPostAuthChannelErrMsg(authId, ret, "unpackRequest");
        goto EXIT_ERR;
    }
    ret = OnRequsetUpdateAuthChannel(authId, &appInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpackRequest failed");
        TransPostAuthChannelErrMsg(authId, ret, "unpackRequest");
        goto EXIT_ERR;
    }
    ret = NotifyOpenAuthChannelSuccess(&appInfo, true);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "NotifyOpenAuthChannelSuccess failed");
        TransPostAuthChannelErrMsg(authId, ret, "NotifyOpenAuthChannelSuccess failed");
        goto EXIT_ERR;
    }
    ret = TransPostAuthChannelMsg(&appInfo, authId, AUTH_CHANNEL_REPLY);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send reply failed");
        TransPostAuthChannelErrMsg(authId, ret, "send reply failed");
        goto EXIT_ERR;
    }
    return;
EXIT_ERR:
    DelAuthChannelInfoByAuthId(authId);
    AuthCloseChannel(authId);
    return;
}

static void OnRecvAuthChannelReply(int64_t authId, const char *data, int32_t len)
{
    if (data == NULL || len <= 0) {
        return;
    }
    AuthChannelInfo info;
    if (GetChannelInfoByAuthId(authId, &info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "can not find channel info by auth id");
        return;
    }
    int32_t ret = TransAuthChannelMsgUnpack(data, &info.appInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpackReply failed");
        goto EXIT_ERR;
    }
    ret = NotifyOpenAuthChannelSuccess(&info.appInfo, false);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "NotifyOpenAuthChannelSuccess failed");
        goto EXIT_ERR;
    }
    return;
EXIT_ERR:
    AuthCloseChannel(authId);
    DelAuthChannelInfoByChanId(info.appInfo.myData.channelId);
    (void)NotifyOpenAuthChannelFailed(info.appInfo.myData.pkgName, info.appInfo.myData.channelId);
    return;
}

static void AuthOnTransDataRecv(int64_t authId, const ConnectOption *option, const AuthTransDataInfo *info)
{
    if (option == NULL || info == NULL) {
        return;
    }
    switch (info->module) {
        case MODULE_AUTH_MSG:
            if (NotifyOnDataReceived(authId, option, info) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv MODULE_AUTH_MSG err");
            }
            break;
        case MODULE_AUTH_CHANNEL:
            if (info->flags == AUTH_CHANNEL_REQ) {
                OnRecvAuthChannelRequest(authId, info->data, info->len);
            } else if (info->flags == AUTH_CHANNEL_REPLY) {
                OnRecvAuthChannelReply(authId, info->data, info->len);
            } else {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "auth channel flags err");
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "auth channel recv err module data");
            return;
    }
}

static void AuthOnCloseChannel(int64_t authId)
{
    AuthChannelInfo dstInfo;
    if (GetChannelInfoByAuthId(authId, &dstInfo) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "auth channel already removed");
        return;
    }
    DelAuthChannelInfoByChanId(dstInfo.appInfo.myData.channelId);
    AuthCloseChannel(authId);
    (void)NofifyCloseAuthChannel(dstInfo.appInfo.myData.pkgName, dstInfo.appInfo.myData.channelId);
}

static AuthTransCallback g_authTransCb = {
    .onTransUdpDataRecv = AuthOnTransDataRecv,
    .onAuthChannelClose = AuthOnCloseChannel,
};

static int32_t GetAppInfo(const char *sessionName, int32_t channelId, AppInfo *appInfo)
{
    if (sessionName == NULL || appInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    appInfo->appType = APP_TYPE_NOT_CARE; // 存疑
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->myData.channelId = channelId;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    if (TransGetUidAndPid(sessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransGetUidAndPid failed");
        return SOFTBUS_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "LnnGetLocalStrInfo failed");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), sessionName) != EOK) {
        return SOFTBUS_ERR;
    }
    if (TransGetPkgNameBySessionName(sessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransGetPkgNameBySessionName failed");
        return SOFTBUS_ERR;
    }
    appInfo->peerData.apiVersion = API_V2;
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), sessionName) != 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t AddAuthChannelInfo(AuthChannelInfo *info)
{
    if (g_authChannelList == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_authChannelList->lock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->appInfo.myData.channelId == info->appInfo.myData.channelId) {
            (void)pthread_mutex_unlock(&g_authChannelList->lock);
            return SOFTBUS_ERR;
        }
    }
    ListAdd(&g_authChannelList->list, &info->node);
    g_authChannelList->cnt++;
    (void)pthread_mutex_unlock(&g_authChannelList->lock);
    return SOFTBUS_OK;
}

static void DelAuthChannelInfoByChanId(int32_t channelId)
{
    if (g_authChannelList == NULL) {
        return;
    }
    if (pthread_mutex_lock(&g_authChannelList->lock) != 0) {
        return;
    }
    AuthChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->appInfo.myData.channelId == channelId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_authChannelList->cnt--;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_authChannelList->lock);
}

static void DelAuthChannelInfoByAuthId(int64_t authId)
{
    if (g_authChannelList == NULL) {
        return;
    }
    if (pthread_mutex_lock(&g_authChannelList->lock) != 0) {
        return;
    }
    AuthChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->authId == authId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_authChannelList->cnt--;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_authChannelList->lock);
}

int32_t TransAuthGetNameByChanId(int32_t chanId, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionLen)
{
    if (pkgName == NULL || sessionName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    AuthChannelInfo info;
    if (GetAuthChannelInfoByChanId(chanId, &info) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (memcpy_s(pkgName, pkgLen, info.appInfo.myData.pkgName, PKG_NAME_SIZE_MAX) != EOK ||
        memcpy_s(sessionName, sessionLen, info.appInfo.myData.sessionName, SESSION_NAME_SIZE_MAX) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransAuthInit(IServerChannelCallBack *cb)
{
    if (cb == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (AuthTransDataRegCallback(TRANS_AUTH_CHANNEL, &g_authTransCb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (g_authChannelList == NULL) {
        g_authChannelList = CreateSoftBusList();
    }
    if (g_authChannelList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_cb == NULL) {
        g_cb = cb;
    }
    return SOFTBUS_OK;
}

void TransAuthDeinit()
{
    g_channelId = 1;
    g_cb = NULL;
}

static int32_t TransPostAuthChannelMsg(const AppInfo *appInfo, int64_t authId, int32_t flag)
{
    if (appInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransPostAuthChannelMsg invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "json failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (TransAuthChannelMsgPack(msg, appInfo) != SOFTBUS_OK) {
        cJSON_Delete(msg);
        return SOFTBUS_ERR;
    }
    char *data = cJSON_PrintUnformatted(msg);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "json failed");
        cJSON_Delete(msg);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    AuthDataHead head = {
        .authId = authId,
        .module = MODULE_AUTH_CHANNEL,
        .flag = flag,
    };
    cJSON_Delete(msg);
    return AuthPostData(&head, (const uint8_t *)data, strlen(data));
}

static void TransPostAuthChannelErrMsg(int64_t authId, int32_t errcode, const char *errMsg)
{
    if (errMsg == NULL) {
        return;
    }
    char cJsonStr[ERR_MSG_MAX_LEN] = {0};
    int32_t ret = TransAuthChannelErrorPack(errcode, errMsg, cJsonStr, ERR_MSG_MAX_LEN); 
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransAuthChannelErrorPack failed");
        return;
    }
    AuthDataHead head = {
        .authId = authId,
        .module = MODULE_AUTH_CHANNEL,
        .flag = AUTH_CHANNEL_REPLY,
    };
    AuthPostData(&head, (const uint8_t *)cJsonStr, strlen(cJsonStr));
}

static AuthChannelInfo *CreateAuthChannelInfo(const char *sessionName)
{
    AuthChannelInfo *info = (AuthChannelInfo *)SoftBusCalloc(sizeof(AuthChannelInfo));
    if (info == NULL) {
        return NULL;
    }
    if (pthread_mutex_lock(&g_authChannelList->lock) != 0) {
        goto EXIT_ERR;
    }
    info->appInfo.myData.channelId = GenerateAuthChannelId();
    if (GetAppInfo(sessionName, info->appInfo.myData.channelId, &info->appInfo) != SOFTBUS_OK) {
        pthread_mutex_unlock(&g_authChannelList->lock);
        goto EXIT_ERR;
    }
    info->isConnOptValid = false;
    pthread_mutex_unlock(&g_authChannelList->lock);
    return info;
EXIT_ERR:
    SoftBusFree(info);
    return NULL;
}

int32_t TransOpenAuthMsgChannel(const char *sessionName, const ConnectOption *connOpt, int32_t *channelId)
{
    if (connOpt == NULL || channelId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    AuthChannelInfo *channel = CreateAuthChannelInfo(sessionName);
    if (channel == NULL) {
        return SOFTBUS_ERR;
    }
    if (memcpy_s(&channel->connOpt, sizeof(ConnectOption), connOpt, sizeof(ConnectOption)) != EOK) {
        SoftBusFree(channel);
        return SOFTBUS_MEM_ERR;
    }
    *channelId = channel->appInfo.myData.channelId;
    channel->isConnOptValid = true;
    int64_t authId = AuthOpenChannel(connOpt);
    if (authId < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "AuthOpenChannel failed");
        SoftBusFree(channel);
        return SOFTBUS_ERR;
    }
    channel->authId = authId;
    if (AddAuthChannelInfo(channel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "AddAuthChannelInfo failed");
        AuthCloseChannel(channel->authId);
        SoftBusFree(channel);
        return SOFTBUS_ERR;
    }
    if (TransPostAuthChannelMsg(&channel->appInfo, authId, AUTH_CHANNEL_REQ) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransPostAuthRequest failed");
        AuthCloseChannel(channel->authId);
        DelAuthChannelInfoByChanId(*channelId);
        SoftBusFree(channel);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransCloseAuthChannel(int32_t channelId)
{
    AuthChannelInfo *channel = NULL;
    if (pthread_mutex_lock(&g_authChannelList->lock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(channel, &g_authChannelList->list, AuthChannelInfo, node) {
        if (channel->appInfo.myData.channelId != channelId) {
            continue;
        }
        int32_t ret = AuthCloseChannel(channel->authId);
        if (ret != SOFTBUS_OK) {
            pthread_mutex_unlock(&g_authChannelList->lock);
            return ret;
        }
        ListDelete(&channel->node);
        g_authChannelList->cnt--;
        NofifyCloseAuthChannel(channel->appInfo.myData.pkgName, channelId);
        SoftBusFree(channel);
        pthread_mutex_unlock(&g_authChannelList->lock);
        return ret;
    }
    pthread_mutex_unlock(&g_authChannelList->lock);
    return SOFTBUS_ERR;
}

int32_t TransSendAuthMsg(int32_t channelId, const char *data, int32_t len)
{
    if (data == NULL || len <= 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    int64_t authId = GetAuthIdByChannelId(channelId);
    if (authId < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Get AuthId failed");
        return SOFTBUS_ERR;
    }

    AuthDataHead head = {
        .authId = authId,
        .module = MODULE_AUTH_MSG,
    };
    return AuthPostData(&head, (const uint8_t *)data, len);
}

int32_t TransNotifyAuthDataSuccess(int32_t channelId)
{
    AuthChannelInfo chanInfo;
    if (GetAuthChannelInfoByChanId(channelId, &chanInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!chanInfo.isConnOptValid) {
        return SOFTBUS_ERR;
    }
    ConnectionAddr addr = {0};
    if (!LnnConvertOptionToAddr(&addr, &chanInfo.connOpt, CONNECTION_ADDR_WLAN)) {
        return SOFTBUS_ERR;
    }
    return LnnNotifyDiscoveryDevice(&addr);
}