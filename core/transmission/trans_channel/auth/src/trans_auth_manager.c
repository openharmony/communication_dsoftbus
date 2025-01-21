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

#include "trans_auth_manager.h"

#include "auth_channel.h"
#include "auth_meta_manager.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_net_builder.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_utils.h"
#include "trans_auth_message.h"
#include "trans_channel_common.h"
#include "trans_channel_limit.h"
#include "trans_event.h"
#include "trans_session_manager.h"
#include "trans_channel_manager.h"
#include "trans_log.h"
#include "trans_lane_manager.h"
#include "wifi_direct_manager.h"

#define AUTH_CHANNEL_REQ 0
#define AUTH_CHANNEL_REPLY 1

#define IPV4_TYPE 1
#define IPV6_TYPE 2

#define AUTH_GROUP_ID "auth group id"
#define AUTH_SESSION_KEY "auth session key"
#define ISHARE_AUTH_SESSION "IShareAuthSession"

const char *g_serviceForAction[] = {
    "IShareAuthSession",
};

#define SERVICE_FOR_ACTION_LEN (sizeof(g_serviceForAction) / sizeof(g_serviceForAction[0]))

typedef struct {
    int32_t channelType;
    int32_t businessType;
    ConfigType configType;
} ConfigTypeMap;

static SoftBusList *g_authChannelList = NULL;
static IServerChannelCallBack *g_cb = NULL;

static void TransPostAuthChannelErrMsg(int32_t authId, int32_t errcode, const char *errMsg);
static int32_t TransPostAuthChannelMsg(const AppInfo *appInfo, int32_t authId, int32_t flag);
static AuthChannelInfo *CreateAuthChannelInfo(const char *sessionName, bool isClient);
static int32_t AddAuthChannelInfo(AuthChannelInfo *info);
static void DelAuthChannelInfoByChanId(int32_t channelId);
static void DelAuthChannelInfoByAuthId(int32_t authId);

SoftBusList *GetAuthChannelListHead(void)
{
    return g_authChannelList;
}

int32_t GetAuthChannelLock(void)
{
    if (g_authChannelList == NULL) {
        TRANS_LOGE(TRANS_SVC, "g_authChannelList not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

void ReleaseAuthChannelLock(void)
{
    if (g_authChannelList == NULL) {
        TRANS_LOGE(TRANS_SVC, "g_authChannelList not init");
        return;
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
}

static int32_t GetAuthChannelInfoByChanId(int32_t channelId, AuthChannelInfo *dstInfo)
{
    if (g_authChannelList == NULL) {
        TRANS_LOGE(TRANS_SVC, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    AuthChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_authChannelList->list, AuthChannelInfo, node) {
        if (info->appInfo.myData.channelId == channelId) {
            if (memcpy_s(dstInfo, sizeof(AuthChannelInfo), info, sizeof(AuthChannelInfo)) != EOK) {
                TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
                (void)SoftBusMutexUnlock(&g_authChannelList->lock);
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t GetAuthIdByChannelId(int32_t channelId)
{
    if (g_authChannelList == NULL) {
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t authId = AUTH_INVALID_ID;
    AuthChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_authChannelList->list, AuthChannelInfo, node) {
        if (info->appInfo.myData.channelId == channelId) {
            authId = info->authId;
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return authId;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    return authId;
}

static int32_t GetChannelInfoByAuthId(int32_t authId, AuthChannelInfo *dstInfo)
{
    if (dstInfo == NULL || g_authChannelList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    AuthChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_authChannelList->list, AuthChannelInfo, node) {
        if (info->authId == authId) {
            if (memcpy_s(dstInfo, sizeof(AuthChannelInfo), info, sizeof(AuthChannelInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_authChannelList->lock);
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t NotifyOpenAuthChannelSuccess(const AppInfo *appInfo, bool isServer)
{
    ChannelInfo channelInfo = {0};
    channelInfo.channelType = CHANNEL_TYPE_AUTH;
    channelInfo.isServer = isServer;
    channelInfo.isEnabled = true;
    channelInfo.channelId = appInfo->myData.channelId;
    channelInfo.peerDeviceId = strlen(appInfo->peerNetWorkId) == 0 ?
        (char *)appInfo->peerData.deviceId : (char *)appInfo->peerNetWorkId;
    channelInfo.peerSessionName = (char *)appInfo->peerData.sessionName;
    channelInfo.businessType = BUSINESS_TYPE_NOT_CARE;
    channelInfo.groupId = (char *)AUTH_GROUP_ID;
    channelInfo.isEncrypt = false;
    channelInfo.sessionKey = (char *)AUTH_SESSION_KEY;
    channelInfo.keyLen = strlen(channelInfo.sessionKey) + 1;
    channelInfo.autoCloseTime = appInfo->autoCloseTime;
    channelInfo.reqId = (char *)appInfo->reqId;
    channelInfo.dataConfig = appInfo->myData.dataConfig;
    channelInfo.timeStart = appInfo->timeStart;
    channelInfo.connectType = appInfo->connectType;
    channelInfo.routeType = appInfo->routeType;
    channelInfo.osType = appInfo->osType;
    return g_cb->OnChannelOpened(appInfo->myData.pkgName, appInfo->myData.pid,
        appInfo->myData.sessionName, &channelInfo);
}

int32_t NotifyOpenAuthChannelFailed(const char *pkgName, int32_t pid, int32_t channelId, int32_t errCode)
{
    return g_cb->OnChannelOpenFailed(pkgName, pid, channelId, CHANNEL_TYPE_AUTH, errCode);
}

static int32_t NotifyCloseAuthChannel(const char *pkgName, int32_t pid, int32_t channelId)
{
    return g_cb->OnChannelClosed(pkgName, pid, channelId, CHANNEL_TYPE_AUTH, MESSAGE_TYPE_NOMAL);
}

static int32_t AuthGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    return g_cb->GetUidAndPidBySessionName(sessionName, uid, pid);
}

static int32_t NotifyOnDataReceived(int32_t authId, const void *data, uint32_t len)
{
    AuthChannelInfo channel;
    int32_t ret = GetChannelInfoByAuthId(authId, &channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "GetChannelInfoByAuthId failed");
        return ret;
    }
    TransReceiveData receiveData;
    receiveData.data = (void *)data;
    receiveData.dataLen = len;
    receiveData.dataType = TRANS_SESSION_BYTES;

    return g_cb->OnDataReceived(channel.appInfo.myData.pkgName, channel.appInfo.myData.pid,
        channel.appInfo.myData.channelId, CHANNEL_TYPE_AUTH, &receiveData);
}

static int32_t CopyPeerAppInfo(AppInfo *recvAppInfo, AppInfo *channelAppInfo)
{
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

static int32_t InitAuthChannelInfo(int32_t authId, AuthChannelInfo *item, AppInfo *appInfo)
{
    item->authId = authId;
    appInfo->myData.channelId = item->appInfo.myData.channelId;
    appInfo->myData.dataConfig = item->appInfo.myData.dataConfig;
    item->connOpt.socketOption.moduleId = AUTH_RAW_P2P_SERVER;
    if (appInfo->linkType == LANE_HML_RAW) {
        item->appInfo.linkType = appInfo->linkType;
        if (memcpy_s(item->appInfo.peerData.addr, IP_LEN, appInfo->peerData.addr, IP_LEN) != EOK ||
            memcpy_s(item->appInfo.myData.addr, IP_LEN, appInfo->myData.addr, IP_LEN) != EOK) {
            TRANS_LOGE(TRANS_SVC, "copy clientIp and serverIp fail, authId=%{public}d", authId);
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t OnRequsetUpdateAuthChannel(int32_t authId, AppInfo *appInfo)
{
    AuthChannelInfo *item = NULL;
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed, authId=%{public}d", authId);
        return SOFTBUS_LOCK_ERR;
    }
    bool exists = false;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->authId == authId) {
            exists = true;
            break;
        }
    }
    int32_t ret = SOFTBUS_OK;
    if (!exists) {
        item = CreateAuthChannelInfo(appInfo->myData.sessionName, false);
        if (item == NULL) {
            TRANS_LOGE(TRANS_SVC, "CreateAuthChannelInfo failed, authId=%{public}d", authId);
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return SOFTBUS_TRANS_AUTH_CREATE_CHANINFO_FAIL;
        }
        ret = InitAuthChannelInfo(authId, item, appInfo);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "init auth channel info failed, ret=%{public}d, authId=%{public}d", ret, authId);
            SoftBusFree(item);
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return ret;
        }
        ret = AddAuthChannelInfo(item);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "AddAuthChannelInfo failed");
            SoftBusFree(item);
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return ret;
        }
    }
    ret = CopyPeerAppInfo(appInfo, &(item->appInfo));
    if (ret != SOFTBUS_OK) {
        ListDelete(&item->node);
        TRANS_LOGE(TRANS_CTRL, "copy peer appInfo failed ret=%{public}d, delete channelId=%{public}" PRId64,
            ret, item->appInfo.myData.channelId);
        SoftBusFree(item);
        g_authChannelList->cnt--;
        (void)SoftBusMutexUnlock(&g_authChannelList->lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    return SOFTBUS_OK;
}

static const ConfigTypeMap g_configTypeMap[] = {
    {CHANNEL_TYPE_AUTH, BUSINESS_TYPE_BYTE, SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH},
    {CHANNEL_TYPE_AUTH, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH},
};

static int32_t FindConfigType(int32_t channelType, int32_t businessType)
{
    uint32_t size = (uint32_t)(sizeof(g_configTypeMap) / sizeof(g_configTypeMap[0]));
    for (uint32_t i = 0; i < size; i++) {
        if ((g_configTypeMap[i].channelType == channelType) && (g_configTypeMap[i].businessType == businessType)) {
            return g_configTypeMap[i].configType;
        }
    }
    return SOFTBUS_CONFIG_TYPE_MAX;
}

static int32_t TransGetLocalConfig(int32_t channelType, int32_t businessType, uint32_t *len)
{
    ConfigType configType = (ConfigType)FindConfigType(channelType, businessType);
    if (configType == SOFTBUS_CONFIG_TYPE_MAX) {
        TRANS_LOGE(TRANS_SVC, "Invalid channelType=%{public}d, businessType=%{public}d", channelType, businessType);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get fail configType=%{public}d", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    *len = maxLen;
    TRANS_LOGI(TRANS_SVC, "get appinfo local config len=%{public}d", *len);
    return SOFTBUS_OK;
}

static int32_t TransAuthFillDataConfig(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_SVC, "appInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    if (appInfo->peerData.dataConfig != 0) {
        uint32_t localDataConfig = 0;
        int32_t ret = TransGetLocalConfig(CHANNEL_TYPE_AUTH, appInfo->businessType, &localDataConfig);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "get local config failed");
            return ret;
        }
        appInfo->myData.dataConfig = MIN(localDataConfig, appInfo->peerData.dataConfig);
        TRANS_LOGI(TRANS_SVC, "fill dataConfig succ. dataConfig=%{public}u", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ?
        SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH : SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH;
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get config failed, configType=%{public}d", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    TRANS_LOGI(TRANS_SVC, "fill dataConfig=%{public}d", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

static void TransAuthCloseChannel(int32_t authId, int32_t linkType, bool isClient)
{
    TRANS_LOGI(TRANS_SVC, "authId=%{public}d, linkType=%{public}d, isClient=%{public}d", authId, linkType, isClient);
    if (linkType == LANE_HML_RAW && isClient) {
        AuthCloseChannel(authId, AUTH_RAW_P2P_CLIENT);
    } else if (linkType == LANE_HML_RAW && !isClient) {
        AuthCloseChannel(authId, AUTH_RAW_P2P_SERVER);
    } else {
        AuthCloseChannel(authId, AUTH);
    }
}

static void TransHandleErrorAndCloseChannel(TransEventExtra *extra, int32_t authId, int32_t linkType, bool isClient,
    int32_t ret)
{
    if (extra != NULL && extra->socketName != NULL) {
        extra->result = EVENT_STAGE_RESULT_FAILED;
        extra->errcode = ret;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, *extra);
    }

    DelAuthChannelInfoByAuthId(authId);
    TransAuthCloseChannel(authId, linkType, isClient);
}

static void TransHandleAuthChannelSetupProcess(TransEventExtra *extra, int32_t authId, AppInfo *appInfo)
{
    int32_t ret = AuthGetUidAndPidBySessionName(
        appInfo->myData.sessionName, &appInfo->myData.uid, &appInfo->myData.pid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "auth get id by sessionName failed and send msg to peer");
        TransPostAuthChannelErrMsg(authId, ret, "session not created");
        TransHandleErrorAndCloseChannel(extra, authId, appInfo->linkType, appInfo->isClient, ret);
        return;
    }
    ret = TransAuthFillDataConfig(appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "TransAuthFillDataConfig failed");
        TransHandleErrorAndCloseChannel(extra, authId, appInfo->linkType, appInfo->isClient, ret);
        return;
    }
    ret = OnRequsetUpdateAuthChannel(authId, appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "update auth channel failed");
        TransPostAuthChannelErrMsg(authId, ret, "unpackRequest");
        TransHandleErrorAndCloseChannel(extra, authId, appInfo->linkType, appInfo->isClient, ret);
        return;
    }
    extra->result = EVENT_STAGE_RESULT_OK;
    extra->channelId = appInfo->myData.channelId;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_START, *extra);
    ret = NotifyOpenAuthChannelSuccess(appInfo, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "Notify Open Auth Channel send request failed, ret=%{public}d", ret);
        TransPostAuthChannelErrMsg(authId, ret, "NotifyOpenAuthChannelSuccess failed");
        TransHandleErrorAndCloseChannel(extra, authId, appInfo->linkType, appInfo->isClient, ret);
        return;
    }
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, *extra);
}

static void OnRecvAuthChannelRequest(int32_t authId, const char *data, int32_t len)
{
    if (data == NULL || len <= 0) {
        return;
    }

    TransEventExtra extra = {
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .socketName = NULL,
        .channelType = CHANNEL_TYPE_AUTH,
        .authId = authId
    };
    char localUdid[UDID_BUF_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) == SOFTBUS_OK) {
        extra.localUdid = localUdid;
    }
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransAuthChannelMsgUnpack(data, &appInfo, len);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "unpackRequest failed");
        TransPostAuthChannelErrMsg(authId, ret, "unpackRequest");
        TransHandleErrorAndCloseChannel(&extra, authId, appInfo.linkType, appInfo.isClient, ret);
        return;
    }
    extra.socketName = appInfo.myData.sessionName;
    extra.peerUdid = appInfo.peerData.deviceId;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_START, extra);
    if (!CheckSessionNameValidOnAuthChannel(appInfo.myData.sessionName)) {
        TRANS_LOGE(TRANS_SVC, "check auth channel pkginfo invalid.");
        TransPostAuthChannelErrMsg(authId, SOFTBUS_TRANS_AUTH_NOTALLOW_OPENED, "check msginfo failed");
        TransHandleErrorAndCloseChannel(&extra, authId, appInfo.linkType, appInfo.isClient,
            SOFTBUS_TRANS_INVALID_SESSION_NAME);
        return;
    }

    TransHandleAuthChannelSetupProcess(&extra, authId, &appInfo);
}

static int32_t TransAuthProcessDataConfig(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_SVC, "appInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (appInfo->businessType != BUSINESS_TYPE_MESSAGE && appInfo->businessType != BUSINESS_TYPE_BYTE) {
        TRANS_LOGI(TRANS_SVC, "invalid businessType=%{public}d", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        appInfo->myData.dataConfig = MIN(appInfo->myData.dataConfig, appInfo->peerData.dataConfig);
        TRANS_LOGI(TRANS_SVC, "process dataConfig succ. dataConfig=%{public}u", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ?
        SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH : SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH;
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get config failed, configType=%{public}d", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    TRANS_LOGI(TRANS_SVC, "process dataConfig=%{public}d", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

static void FillExtraByAuthChannelErrorEnd(TransEventExtra *extra, AuthChannelInfo *info, int32_t ret)
{
    if (extra == NULL || info == NULL) {
        TRANS_LOGE(TRANS_SVC, "invalid param.");
        return;
    }
    extra->result = EVENT_STAGE_RESULT_FAILED;
    extra->errcode = ret;
    extra->localUdid = info->appInfo.myData.deviceId;
    if (strlen(info->appInfo.peerVersion) == 0) {
        TransGetRemoteDeviceVersion(extra->peerUdid, CATEGORY_UDID, info->appInfo.peerVersion,
            sizeof(info->appInfo.peerVersion));
    }
    extra->peerDevVer = info->appInfo.peerVersion;
}

static void InitExtra(TransEventExtra *extra, const AuthChannelInfo *info, int32_t authId)
{
    extra->peerNetworkId = NULL;
    extra->calleePkg = NULL;
    extra->callerPkg = NULL;
    extra->socketName = info->appInfo.myData.sessionName;
    extra->channelId = info->appInfo.myData.channelId;
    extra->channelType = CHANNEL_TYPE_AUTH;
    extra->authId = authId;
    extra->linkType = info->connOpt.type;
    extra->osType = (info->appInfo.osType < 0) ? UNKNOW_OS_TYPE : info->appInfo.osType;
}

static void ChannelReplyErrProc(TransEventExtra *extra, int32_t errorCode, AuthChannelInfo *info, int32_t authId)
{
    FillExtraByAuthChannelErrorEnd(extra, info, errorCode);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, *extra);
    TransAuthCloseChannel(authId, info->appInfo.linkType, info->isClient);
    (void)TransLaneMgrDelLane(info->appInfo.myData.channelId, CHANNEL_TYPE_AUTH, true);
    DelAuthChannelInfoByChanId((int32_t)(info->appInfo.myData.channelId));
    (void)NotifyOpenAuthChannelFailed((const char *)(info->appInfo.myData.pkgName),
        (int32_t)(info->appInfo.myData.pid), (int32_t)(info->appInfo.myData.channelId), errorCode);
}

int32_t TransAuthGetPeerUdidByChanId(int32_t channelId, char *peerUdid, uint32_t len)
{
    if (len < DEVICE_ID_SIZE_MAX || peerUdid == NULL) {
        TRANS_LOGE(TRANS_SVC, "param err");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthChannelInfo info;
    int32_t ret = GetAuthChannelInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get channel info by chanId failed. chanId=%{public}d", channelId);
        return ret;
    }
    if (strlen(info.appInfo.peerUdid) != 0) {
        if (memcpy_s(peerUdid, len, info.appInfo.peerUdid, DEVICE_ID_SIZE_MAX) != EOK) {
            return SOFTBUS_MEM_ERR;
        }
    } else {
        if (memcpy_s(peerUdid, len, info.appInfo.peerData.deviceId, DEVICE_ID_SIZE_MAX) != EOK) {
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

static void LnnSvrJoinCallback(const ConnectionAddr *connAddr, int32_t errCode)
{
    if (connAddr == NULL) {
        TRANS_LOGE(TRANS_SVC, "invalid param");
        return;
    }
    TRANS_LOGI(TRANS_SVC, "LnnSvrJoinCallback enter");
    AuthChannelInfo info;
    int32_t ret = GetAuthChannelInfoByChanId(connAddr->info.session.channelId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get channel info by chanId failed. chanId=%{public}d", connAddr->info.session.channelId);
        return;
    }

    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    InitExtra(&extra, &info, info.authId);
    extra.peerUdid = strlen(info.appInfo.peerUdid) != 0 ? info.appInfo.peerUdid : info.appInfo.peerData.deviceId;
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "LnnServerJoinExt failed, chanId=%{public}d, errCode=%{public}d",
            connAddr->info.session.channelId, errCode);
    }
    extra.result = EVENT_STAGE_RESULT_OK;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
    ret = NotifyOpenAuthChannelSuccess(&info.appInfo, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "NotifyOpenAuthChannelSuccess failed");
        ChannelReplyErrProc(&extra, ret, &info, info.authId);
    }
}

static int32_t UpdateChannelInfo(int32_t authId, const AuthChannelInfo *info)
{
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    AuthChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->authId == authId) {
            if (memcpy_s(&(item->appInfo), sizeof(item->appInfo), &(info->appInfo), sizeof(info->appInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_authChannelList->lock);
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t AdaptLnnServerJoinExt(int64_t channelId)
{
    ConnectionAddr connAddr;
    (void)memset_s(&connAddr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    connAddr.type = CONNECTION_ADDR_SESSION;
    connAddr.info.session.channelId = channelId;
    LnnServerJoinExtCallBack svrJoinCallBack = {
        .lnnServerJoinExtCallback = LnnSvrJoinCallback,
    };
    return LnnServerJoinExt(&connAddr, &svrJoinCallBack);
}

static void OnRecvAuthChannelReply(int32_t authId, const char *data, int32_t len)
{
    if (data == NULL || len <= 0) {
        return;
    }
    AuthChannelInfo info;
    if (GetChannelInfoByAuthId(authId, &info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "can not find channel info by auth id");
        return;
    }
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    InitExtra(&extra, &info, authId);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
    int32_t ret = TransAuthChannelMsgUnpack(data, &info.appInfo, len);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "unpackReply failed");
        ChannelReplyErrProc(&extra, ret, &info, authId);
        return;
    }
    extra.peerUdid = strlen(info.appInfo.peerUdid) != 0 ? info.appInfo.peerUdid : info.appInfo.peerData.deviceId;
    ret = TransAuthProcessDataConfig(&info.appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "ProcessDataConfig failed");
        ChannelReplyErrProc(&extra, ret, &info, authId);
        return;
    }
    extra.result = EVENT_STAGE_RESULT_OK;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);

    if (info.accountInfo) {
        TRANS_LOGI(TRANS_SVC, "accountInfo=%{public}d, authId=%{public}d, channelId=%{public}" PRId64,
            info.accountInfo, info.authId, info.appInfo.myData.channelId);
        if (UpdateChannelInfo(authId, &info) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "update channelInfo failed, authId=%{public}d", info.authId);
            return;
        }
        int64_t channelId = info.appInfo.myData.channelId;
        ret = AdaptLnnServerJoinExt(channelId);
        if (ret == SOFTBUS_OK) {
            return;
        }
        TRANS_LOGI(TRANS_SVC, "adapt LnnServerJoinExt fail, channelId=%{public}" PRId64, channelId);
    }

    ret = NotifyOpenAuthChannelSuccess(&info.appInfo, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "NotifyOpenAuthChannelSuccess failed");
        ChannelReplyErrProc(&extra, ret, &info, authId);
    }
}

static void OnAuthChannelDataRecv(int32_t authId, const AuthChannelData *data)
{
    if (data == NULL || data->data == NULL || data->len < 1) {
        TRANS_LOGW(TRANS_SVC, "invalid param.");
        return;
    }

    if (data->flag == AUTH_CHANNEL_REQ) {
        OnRecvAuthChannelRequest(authId, (const char *)data->data, (int32_t)data->len);
    } else if (data->flag == AUTH_CHANNEL_REPLY) {
        OnRecvAuthChannelReply(authId, (const char *)data->data, (int32_t)data->len);
    } else {
        TRANS_LOGE(TRANS_SVC, "auth channel flags err, authId=%{public}d", authId);
    }
}

static void OnAuthMsgDataRecv(int32_t authId, const AuthChannelData *data)
{
    if (data == NULL || data->data == NULL) {
        return;
    }
    if (NotifyOnDataReceived(authId, data->data, data->len) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "recv MODULE_AUTH_MSG err. authId=%{public}d", authId);
    }
}

static void OnDisconnect(int32_t authId)
{
    AuthChannelInfo dstInfo;
    if (GetChannelInfoByAuthId(authId, &dstInfo) != EOK) {
        TRANS_LOGE(TRANS_SVC, "channel already removed. authId=%{public}d", authId);
        return;
    }
    TRANS_LOGI(TRANS_SVC, "recv channel disconnect event. authId=%{public}d", authId);

    // If it is an ishare session, clean up the auth manager
    if (strcmp(dstInfo.appInfo.myData.sessionName, ISHARE_AUTH_SESSION) == 0) {
        DelAuthMetaManagerByConnectionId(authId);
    }
    TransAuthCloseChannel(authId, dstInfo.appInfo.linkType, dstInfo.isClient);
    DelAuthChannelInfoByChanId((int32_t)(dstInfo.appInfo.myData.channelId));
    (void)NotifyCloseAuthChannel((const char *)dstInfo.appInfo.myData.pkgName,
        (int32_t)dstInfo.appInfo.myData.pid, (int32_t)dstInfo.appInfo.myData.channelId);
}

int32_t GetAppInfo(const char *sessionName, int32_t channelId, AppInfo *appInfo, bool isClient)
{
    if (sessionName == NULL || appInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    appInfo->appType = APP_TYPE_NOT_CARE;
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->channelType = CHANNEL_TYPE_AUTH;
    appInfo->myData.channelId = channelId;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->autoCloseTime = 0;
    int32_t ret = TransGetUidAndPid(sessionName, &appInfo->myData.uid, &appInfo->myData.pid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "TransGetUidAndPid failed");
        return ret;
    }
    ret = TransGetPkgNameBySessionName(sessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "TransGetPkgNameBySessionName failed");
        return ret;
    }
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, appInfo->myData.deviceId, sizeof(appInfo->myData.deviceId));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "LnnGetLocalStrInfo failed");
        return ret;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), sessionName) != EOK) {
        TRANS_LOGE(TRANS_SVC, "copy sessionName failed");
        return SOFTBUS_STRCPY_ERR;
    }
    appInfo->peerData.apiVersion = API_V2;
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), sessionName) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    ret = TransGetLocalConfig(appInfo->channelType, appInfo->businessType, &appInfo->myData.dataConfig);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t AddAuthChannelInfo(AuthChannelInfo *info)
{
    if (g_authChannelList == NULL || info == NULL) {
        TRANS_LOGE(TRANS_SVC, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "fail to lock authChannelList.");
        return SOFTBUS_LOCK_ERR;
    }
    AuthChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->appInfo.myData.channelId == info->appInfo.myData.channelId) {
            (void)SoftBusMutexLock(&g_authChannelList->lock);
            TRANS_LOGE(TRANS_SVC, "found auth channel, channelId=%{public}" PRId64,
                info->appInfo.myData.channelId);
            return SOFTBUS_TRANS_INVALID_CHANNEL_ID;
        }
    }
    ListAdd(&g_authChannelList->list, &info->node);
    TRANS_LOGI(TRANS_CTRL, "add channelId=%{public}" PRId64 ", isClient=%{public}d",
        info->appInfo.myData.channelId, info->appInfo.isClient);
    g_authChannelList->cnt++;
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    return SOFTBUS_OK;
}

static void DelAuthChannelInfoByChanId(int32_t channelId)
{
    if (g_authChannelList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return;
    }
    AuthChannelInfo *item = NULL;
    AuthChannelInfo *tmp = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, tmp, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->appInfo.myData.channelId == channelId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL, "delete channelId=%{public}d", channelId);
            SoftBusFree(item);
            g_authChannelList->cnt--;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
}

static void DelAuthChannelInfoByAuthId(int32_t authId)
{
    if (g_authChannelList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return;
    }
    AuthChannelInfo *item = NULL;
    AuthChannelInfo *tmp = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, tmp, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->authId == authId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL, "delete authId = %{public}d", item->authId);
            SoftBusFree(item);
            g_authChannelList->cnt--;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
}

int32_t TransAuthGetNameByChanId(int32_t chanId, char *pkgName, char *sessionName, uint16_t pkgLen, uint16_t sessionLen)
{
    if (pkgName == NULL || sessionName == NULL) {
        TRANS_LOGE(TRANS_SVC, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    AuthChannelInfo info;
    int32_t ret = GetAuthChannelInfoByChanId(chanId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get channel info by chanId failed. chanId=%{public}d", chanId);
        return ret;
    }

    if (memcpy_s(pkgName, pkgLen, info.appInfo.myData.pkgName, PKG_NAME_SIZE_MAX) != EOK ||
        memcpy_s(sessionName, sessionLen, info.appInfo.myData.sessionName, SESSION_NAME_SIZE_MAX) != EOK) {
        TRANS_LOGE(TRANS_SVC, "memcpy_s failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransAuthInit(IServerChannelCallBack *cb)
{
    if (cb == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    AuthChannelListener channelListener = {
        .onDataReceived = OnAuthChannelDataRecv,
        .onDisconnected = OnDisconnect,
    };
    AuthChannelListener msgListener = {
        .onDataReceived = OnAuthMsgDataRecv,
        .onDisconnected = OnDisconnect,
    };
    if (RegAuthChannelListener(MODULE_AUTH_CHANNEL, &channelListener) != SOFTBUS_OK ||
        RegAuthChannelListener(MODULE_AUTH_MSG, &msgListener) != SOFTBUS_OK) {
        UnregAuthChannelListener(MODULE_AUTH_CHANNEL);
        UnregAuthChannelListener(MODULE_AUTH_MSG);
        return SOFTBUS_TRANS_REG_AUTH_CHANNEL_LISTERNER_FAILED;
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

void TransAuthDeinit(void)
{
    UnregAuthChannelListener(MODULE_AUTH_CHANNEL);
    UnregAuthChannelListener(MODULE_AUTH_MSG);
    DestroySoftBusList(g_authChannelList);
    g_authChannelList = NULL;
    g_cb = NULL;
}

static int32_t TransPostAuthChannelMsg(const AppInfo *appInfo, int32_t authId, int32_t flag)
{
    if (appInfo == NULL) {
        TRANS_LOGW(TRANS_SVC, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        TRANS_LOGE(TRANS_SVC, "json failed");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = TransAuthChannelMsgPack(msg, appInfo);
    if (ret != SOFTBUS_OK) {
        cJSON_Delete(msg);
        TRANS_LOGE(TRANS_SVC, "tran channel msg pack failed");
        return ret;
    }
    char *data = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    if (data == NULL) {
        TRANS_LOGE(TRANS_SVC, "json failed");
        return SOFTBUS_PARSE_JSON_ERR;
    }

    AuthChannelData channelData = {
        .module = MODULE_AUTH_CHANNEL,
        .flag = flag,
        .seq = 0,
        .len = strlen(data) + 1,
        .data = (const uint8_t *)data,
    };
    ret = AuthPostChannelData(authId, &channelData);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "auth post channel data fail");
        cJSON_free(data);
        return ret;
    }
    cJSON_free(data);
    return SOFTBUS_OK;
}

static void TransPostAuthChannelErrMsg(int32_t authId, int32_t errcode, const char *errMsg)
{
    if (errMsg == NULL) {
        return;
    }
    char cJsonStr[ERR_MSG_MAX_LEN] = {0};
    int32_t ret = TransAuthChannelErrorPack(errcode, errMsg, cJsonStr, ERR_MSG_MAX_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "TransAuthChannelErrorPack failed");
        return;
    }
    AuthChannelData channelData = {
        .module = MODULE_AUTH_CHANNEL,
        .flag = AUTH_CHANNEL_REPLY,
        .seq = 0,
        .len = strlen(cJsonStr) + 1,
        .data = (const uint8_t *)cJsonStr,
    };
    if (AuthPostChannelData(authId, &channelData) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "auth post channel data fail");
    }
}

static AuthChannelInfo *CreateAuthChannelInfo(const char *sessionName, bool isClient)
{
    AuthChannelInfo *info = (AuthChannelInfo *)SoftBusCalloc(sizeof(AuthChannelInfo));
    if (info == NULL) {
        return NULL;
    }
    info->appInfo.myData.channelId = GenerateChannelId(true);
    if (info->appInfo.myData.channelId <= INVALID_CHANNEL_ID) {
        TRANS_LOGE(TRANS_SVC, "channelId is invalid");
        goto EXIT_ERR;
    }
    if (GetAppInfo(sessionName, info->appInfo.myData.channelId, &info->appInfo, isClient) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    info->isClient = isClient;
    return info;
EXIT_ERR:
    SoftBusFree(info);
    return NULL;
}

static void FillAndReportEventStart(const char *sessionName, int32_t *channelId, int32_t connType,
    TransEventExtra *extra, AuthChannelInfo *channel)
{
    extra->peerNetworkId = NULL;
    extra->calleePkg = NULL;
    extra->callerPkg = NULL;
    extra->socketName = sessionName;
    extra->channelId = *channelId;
    extra->channelType = CHANNEL_TYPE_AUTH;
    extra->linkType = connType;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, *extra);
}

static void FillAndReportEventEnd(int32_t authId, TransEventExtra *extra)
{
    extra->result = EVENT_STAGE_RESULT_OK;
    extra->authId = authId;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, *extra);
}

static bool CheckForAuthWithParam(const char *sessionName, const LaneConnInfo *connInfo, const int32_t *channelId)
{
    if (sessionName == NULL || connInfo == NULL || channelId == NULL) {
        TRANS_LOGE(TRANS_SVC, "CheckForAuthWithParam invalid param");
        return false;
    }
    if (g_authChannelList == NULL) {
        TRANS_LOGE(TRANS_SVC, "CheckForAuthWithParam g_authChannelList is null");
        return false;
    }
    if (connInfo->type != LANE_HML_RAW) {
        TRANS_LOGE(TRANS_SVC, "CheckForAuthWithParam connInfo->type is %{public}d", connInfo->type);
        return false;
    }
    return true;
}

static int32_t TransFillAuthChannelInfo(AuthChannelInfo *channel, const LaneConnInfo *connInfo,
    const int32_t *channelId, bool accountInfo)
{
    if (channel == NULL || connInfo == NULL || channelId == NULL) {
        TRANS_LOGE(TRANS_SVC, "TransFillAuthChannelInfo invalid parm");
        return SOFTBUS_INVALID_PARAM;
    }

    (void)memset_s(channel->appInfo.reqId, REQ_ID_SIZE_MAX, 0, REQ_ID_SIZE_MAX);
    channel->appInfo.myData.channelId = *channelId;
    channel->appInfo.timeStart = GetSoftbusRecordTimeMillis();
    channel->appInfo.linkType = connInfo->type;
    channel->appInfo.routeType = WIFI_P2P;
    channel->connOpt.socketOption.moduleId = AUTH_RAW_P2P_CLIENT;
    channel->accountInfo = accountInfo;

    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, channel->appInfo.peerNetWorkId,
                           sizeof(channel->appInfo.peerNetWorkId)) != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SVC, "LnnGetLocalStrInfo STRING_KEY_NETWORKID failed");
    }

    if (strcpy_s(channel->appInfo.myData.addr, IP_LEN, connInfo->connInfo.rawWifiDirect.localIp) != EOK) {
        TRANS_LOGE(TRANS_SVC, "TransFillAuthChannelInfo strcpy_s localIp failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(channel->appInfo.peerData.addr, IP_LEN, connInfo->connInfo.rawWifiDirect.peerIp) != EOK) {
        TRANS_LOGE(TRANS_SVC, "TransFillAuthChannelInfo strcpy_s perrIp failed");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t PostAuthMsg(AuthChannelInfo *channel, TransEventExtra *extra, const LaneConnInfo *connInfo,
    const int32_t *channelId)
{
    int32_t authId = AuthOpenChannelWithAllIp(connInfo->connInfo.rawWifiDirect.localIp,
        connInfo->connInfo.rawWifiDirect.peerIp, connInfo->connInfo.rawWifiDirect.port);
    if (authId < 0) {
        TRANS_LOGE(TRANS_SVC, "AuthOpenChannelWithAllIp failed");
        SoftBusFree(channel);
        return SOFTBUS_TRANS_OPEN_AUTH_CHANNEL_FAILED;
    }
    extra->result = EVENT_STAGE_RESULT_OK;
    extra->authId = authId;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, *extra);
    channel->authId = authId;
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "SoftBusMutexLock failed");
        TransAuthCloseChannel(channel->authId, LANE_HML_RAW, true);
        SoftBusFree(channel);
        return SOFTBUS_LOCK_ERR;
    }
    if (AddAuthChannelInfo(channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "AddAuthChannelInfo failed");
        (void)SoftBusMutexUnlock(&g_authChannelList->lock);
        TransAuthCloseChannel(channel->authId, LANE_HML_RAW, true);
        SoftBusFree(channel);
        return SOFTBUS_TRANS_AUTH_ADD_CHANINFO_FAIL;
    }
    extra->result = 0;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, *extra);
    if (TransPostAuthChannelMsg(&channel->appInfo, authId, AUTH_CHANNEL_REQ) !=SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "TransPostAuthRequest failed");
        DelAuthChannelInfoByChanId(*channelId);
        (void)SoftBusMutexUnlock(&g_authChannelList->lock);
        TransAuthCloseChannel(authId, LANE_HML_RAW, true);
        return SOFTBUS_TRANS_AUTH_POST_CHANMSG_FAIL;
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    return SOFTBUS_OK;
}

int32_t TransOpenAuthMsgChannelWithPara(const char *sessionName, const LaneConnInfo *connInfo, int32_t *channelId,
    bool accountInfo)
{
    if (!CheckForAuthWithParam(sessionName, connInfo, channelId)) {
        TRANS_LOGE(TRANS_SVC, "TransOpenAuthMsgChannelWithPara CheckForAuthWithParam fail");
        return SOFTBUS_INVALID_PARAM;
    }

    AuthChannelInfo *channel = CreateAuthChannelInfo(sessionName, true);
    if (channel == NULL) {
        TRANS_LOGE(TRANS_SVC, "TransOpenAuthMsgChannelWithPara CreateAuthChannelInfo fail");
        return SOFTBUS_TRANS_AUTH_CREATE_CHANINFO_FAIL;
    }
    if (TransFillAuthChannelInfo(channel, connInfo, channelId, accountInfo) != SOFTBUS_OK) {
        SoftBusFree(channel);
        TRANS_LOGE(TRANS_SVC, "TransOpenAuthMsgChannelWithPara TransFillAuthChannelInfo failed");
        return SOFTBUS_TRANS_AUTH_FILL_CHANINFO_FAIL;
    }

    TransEventExtra extra = {
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .socketName = sessionName,
        .channelId = *channelId,
        .channelType = CHANNEL_TYPE_AUTH,
        .linkType = CONNECT_HML
     };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);

    int32_t ret = PostAuthMsg(channel, &extra, connInfo, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "PostAuthMsg failed, ret=%{public}d", ret);
        return ret;
    }
    extra.result = EVENT_STAGE_RESULT_OK;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, extra);
    return SOFTBUS_OK;
}

static AuthChannelInfo *TransOpenAuthChannelPrepareParam(const char *sessionName, const ConnectOption *connOpt,
    int32_t *channelId, const char *reqId)
{
    AuthChannelInfo *channel = CreateAuthChannelInfo(sessionName, true);
    TRANS_CHECK_AND_RETURN_RET_LOGE(channel != NULL, NULL, TRANS_SVC, "fail to add pid");
    if (strcpy_s(channel->appInfo.reqId, REQ_ID_SIZE_MAX, reqId) != EOK ||
        memcpy_s(&channel->connOpt, sizeof(ConnectOption), connOpt, sizeof(ConnectOption)) != EOK) {
        SoftBusFree(channel);
        TRANS_LOGE(TRANS_SVC, "fail to copy appInfo and connOpt.");
        return NULL;
    }
    *channelId = (int32_t)channel->appInfo.myData.channelId;
    channel->appInfo.timeStart = GetSoftbusRecordTimeMillis();
    channel->appInfo.connectType = connOpt->type;
    return channel;
}

int32_t TransOpenAuthMsgChannel(const char *sessionName, const ConnectOption *connOpt,
    int32_t *channelId, const char *reqId)
{
    if (connOpt == NULL || channelId == NULL || connOpt->type != CONNECT_TCP || g_authChannelList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    AuthChannelInfo *channel = TransOpenAuthChannelPrepareParam(sessionName, connOpt, channelId, reqId);
    if (channel == NULL) {
        TRANS_LOGE(TRANS_SVC, "fail to get auth channel info.");
        return SOFTBUS_INVALID_PARAM;
    }
    TransEventExtra extra;
    FillAndReportEventStart(sessionName, channelId, connOpt->type, &extra, channel);
    int32_t authId = AuthOpenChannel(connOpt->socketOption.addr, connOpt->socketOption.port);
    if (authId < 0) {
        TRANS_LOGE(TRANS_SVC, "AuthOpenChannel failed");
        SoftBusFree(channel);
        return SOFTBUS_TRANS_OPEN_AUTH_CHANNEL_FAILED;
    }
    FillAndReportEventEnd(authId, &extra);
    channel->authId = authId;
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "SoftBusMutexLock failed");
        TransAuthCloseChannel(channel->authId, LANE_HML_RAW, true);
        SoftBusFree(channel);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = AddAuthChannelInfo(channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "AddAuthChannelInfo failed");
        TransAuthCloseChannel(channel->authId, LANE_HML_RAW, true);
        SoftBusFree(channel);
        (void)SoftBusMutexUnlock(&g_authChannelList->lock);
        return ret;
    }
    extra.result = 0;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, extra);
    ret = TransPostAuthChannelMsg(&channel->appInfo, authId, AUTH_CHANNEL_REQ);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "TransPostAuthRequest failed");
        TransAuthCloseChannel(channel->authId, LANE_HML_RAW, true);
        DelAuthChannelInfoByChanId(*channelId);
        (void)SoftBusMutexUnlock(&g_authChannelList->lock);
        return ret;
    }
    extra.result = EVENT_STAGE_RESULT_OK;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, extra);
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    return SOFTBUS_OK;
}

int32_t TransCloseAuthChannel(int32_t channelId)
{
    AuthChannelInfo *channel = NULL;
    AuthChannelInfo *tmp = NULL;
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(channel, tmp, &g_authChannelList->list, AuthChannelInfo, node) {
        if (channel->appInfo.myData.channelId != channelId) {
            continue;
        }
        ListDelete(&channel->node);
        TRANS_LOGI(TRANS_CTRL, "delete channelId=%{public}d, authId=%{public}d", channelId, channel->authId);
        g_authChannelList->cnt--;
        // If it is an ishare session, clean up the auth manager
        if (strcmp(channel->appInfo.myData.sessionName, ISHARE_AUTH_SESSION) == 0) {
            DelAuthMetaManagerByConnectionId(channel->authId);
        }
        TransAuthCloseChannel(channel->authId, channel->appInfo.linkType, channel->isClient);
        NotifyCloseAuthChannel(channel->appInfo.myData.pkgName, channel->appInfo.myData.pid, channelId);
        SoftBusFree(channel);
        (void)SoftBusMutexUnlock(&g_authChannelList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransSendAuthMsg(int32_t channelId, const char *msg, int32_t len)
{
    if (msg == NULL || len <= 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t authId = GetAuthIdByChannelId(channelId);
    if (authId < 0) {
        TRANS_LOGE(TRANS_SVC, "Get AuthId failed");
        return SOFTBUS_TRANS_AUTH_CHANNEL_NOT_FOUND;
    }

    AuthChannelData channelData = {
        .module = MODULE_AUTH_MSG,
        .flag = 0,
        .seq = 0,
        .len = (uint32_t)len,
        .data = (const uint8_t *)msg,
    };
    int32_t ret = AuthPostChannelData(authId, &channelData);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "auth post channel data fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransAuthGetConnOptionByChanId(int32_t channelId, ConnectOption *connOpt)
{
    AuthChannelInfo chanInfo;
    int32_t ret = GetAuthChannelInfoByChanId(channelId, &chanInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get auth channel info by channelId fail. channelId=%{public}d", channelId);
        return ret;
    }

    if (!chanInfo.isClient) {
        TRANS_LOGE(TRANS_SVC, "auth channel of conn opt invalid");
        return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }

    if (memcpy_s(connOpt, sizeof(ConnectOption), &(chanInfo.connOpt), sizeof(ConnectOption)) != EOK) {
        TRANS_LOGE(TRANS_SVC, "auth channel connopt memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransNotifyAuthDataSuccess(int32_t channelId, const ConnectOption *connOpt)
{
    if (connOpt == NULL) {
        TRANS_LOGW(TRANS_SVC, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    if (!LnnConvertOptionToAddr(&addr, connOpt, CONNECTION_ADDR_WLAN)) {
        TRANS_LOGE(TRANS_SVC, "channelId convert addr fail. channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_CHANNELID_CONVERT_ADDR_FAILED;
    }
    LnnDfxDeviceInfoReport infoReport;
    (void)memset_s(&infoReport, sizeof(LnnDfxDeviceInfoReport), 0, sizeof(LnnDfxDeviceInfoReport));
    return LnnNotifyDiscoveryDevice(&addr, &infoReport, true);
}

int32_t TransAuthGetAppInfoByChanId(int32_t channelId, AppInfo *appInfo)
{
    if (appInfo == NULL || g_authChannelList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    AuthChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_authChannelList->list, AuthChannelInfo, node) {
        if (info->appInfo.myData.channelId == channelId) {
            if (memcpy_s(appInfo, sizeof(AppInfo), &info->appInfo, sizeof(AppInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&g_authChannelList->lock);
                TRANS_LOGE(TRANS_SVC, "auth channel appinfo memcpy fail");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    TRANS_LOGE(TRANS_CTRL, "Auth channel not find: channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransAuthGetConnIdByChanId(int32_t channelId, int32_t *connId)
{
    if ((g_authChannelList == NULL) || (connId == NULL)) {
        TRANS_LOGE(TRANS_SVC, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get mutex lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    AuthChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->appInfo.myData.channelId == channelId) {
            *connId = item->authId;
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    TRANS_LOGE(TRANS_SVC, "get connid failed");
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t CheckIsWifiAuthChannel(ConnectOption *connInfo)
{
    if (connInfo == NULL || connInfo->socketOption.moduleId != AUTH) {
        TRANS_LOGE(
            TRANS_SVC, "invalid param, moduleId=%{public}d", connInfo == NULL ? -1 : connInfo->socketOption.moduleId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_authChannelList == NULL) {
        TRANS_LOGE(TRANS_SVC, "not init auth channel");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get mutex lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    AuthChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_authChannelList->list, AuthChannelInfo, node) {
        if (info->connOpt.socketOption.port == connInfo->socketOption.port &&
            memcmp(info->connOpt.socketOption.addr, connInfo->socketOption.addr,
            strlen(connInfo->socketOption.addr)) == 0) {
            TRANS_LOGI(TRANS_SVC, "auth channel type is wifi");
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    TRANS_LOGE(TRANS_SVC, "auth channel is not exit");
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t TransSetAuthChannelReplyCnt(int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_authChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_authChannelList is NULL");
    int32_t ret = SoftBusMutexLock(&g_authChannelList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    AuthChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->appInfo.myData.channelId == channelId) {
            item->appInfo.waitOpenReplyCnt = CHANNEL_OPEN_SUCCESS;
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    TRANS_LOGE(TRANS_SVC, "Auth channel not find: channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransDealAuthChannelOpenResult(int32_t channelId, int32_t openResult)
{
    AuthChannelInfo info;
    (void)memset_s(&info, sizeof(AuthChannelInfo), 0, sizeof(AuthChannelInfo));
    int32_t ret = GetAuthChannelInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get auth channel failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    ret = TransSetAuthChannelReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "update cnt failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    TransEventExtra extra = {
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .channelType = CHANNEL_TYPE_AUTH,
        .authId = info.authId,
        .result = EVENT_STAGE_RESULT_OK,
        .channelId = info.appInfo.myData.channelId,
        .socketName = info.appInfo.myData.sessionName,
        .peerUdid = info.appInfo.peerData.deviceId,
    };
    if (openResult != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "open auth channel failed, openResult=%{public}d", openResult);
        TransPostAuthChannelErrMsg(info.authId, openResult, "open auth channel failed");
        TransHandleErrorAndCloseChannel(&extra, info.authId, info.appInfo.linkType, info.appInfo.isClient, openResult);
        return SOFTBUS_OK;
    }
    ret = TransPostAuthChannelMsg(&info.appInfo, info.authId, AUTH_CHANNEL_REPLY);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "send reply failed, ret=%{public}d", ret);
        TransHandleErrorAndCloseChannel(&extra, info.authId, info.appInfo.linkType, info.appInfo.isClient, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TransCheckAuthChannelOpenStatus(int32_t channelId, int32_t *curCount)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_authChannelList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_authChannelList is null");
    int32_t ret = SoftBusMutexLock(&g_authChannelList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    AuthChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authChannelList->list, AuthChannelInfo, node) {
        if (item->appInfo.myData.channelId == channelId) {
            if (item->appInfo.waitOpenReplyCnt != CHANNEL_OPEN_SUCCESS) {
                item->appInfo.waitOpenReplyCnt++;
            }
            *curCount = item->appInfo.waitOpenReplyCnt;
            (void)SoftBusMutexUnlock(&g_authChannelList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    TRANS_LOGE(TRANS_SVC, "Auth channel not find: channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

void TransAsyncAuthChannelTask(int32_t channelId)
{
    int32_t curCount = 0;
    int32_t ret = TransCheckAuthChannelOpenStatus(channelId, &curCount);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "check auth channel open failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return;
    }
    if (curCount == CHANNEL_OPEN_SUCCESS) {
        TRANS_LOGI(TRANS_CTRL, "open auth channel success, channelId=%{public}d", channelId);
        return;
    }
    AuthChannelInfo info;
    (void)memset_s(&info, sizeof(AuthChannelInfo), 0, sizeof(AuthChannelInfo));
    ret = GetAuthChannelInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get auth channel failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return;
    }
    if (curCount >= LOOPER_REPLY_CNT_MAX) {
        TRANS_LOGE(TRANS_CTRL, "open auth channel timeout, channelId=%{public}d", channelId);
        TransPostAuthChannelErrMsg(
            info.authId,  SOFTBUS_TRANS_OPEN_CHANNEL_NEGTIATE_TIMEOUT, "open auth channel failed");
        DelAuthChannelInfoByAuthId(info.authId);
        TransAuthCloseChannel(info.authId, info.appInfo.linkType, info.isClient);
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "Open channelId=%{public}d not finished, generate new task and waiting", channelId);
    uint32_t delayTime = (curCount <= LOOPER_SEPARATE_CNT) ? FAST_INTERVAL_MILLISECOND : SLOW_INTERVAL_MILLISECOND;
    TransCheckChannelOpenToLooperDelay(channelId, CHANNEL_TYPE_AUTH, delayTime);
}

static void TransAuthDestroyChannelList(const ListNode *destroyList)
{
    TRANS_CHECK_AND_RETURN_LOGE(
        (destroyList != NULL && !IsListEmpty(destroyList)), TRANS_CTRL, "destroyList is null");

    AuthChannelInfo *destroyNode = NULL;
    AuthChannelInfo *nextDestroyNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(destroyNode, nextDestroyNode, destroyList, AuthChannelInfo, node) {
        ListDelete(&(destroyNode->node));
        TransAuthCloseChannel(destroyNode->authId, destroyNode->appInfo.linkType, destroyNode->isClient);
        NotifyCloseAuthChannel(destroyNode->appInfo.myData.pkgName,
            destroyNode->appInfo.myData.pid, destroyNode->appInfo.myData.channelId);

        if (destroyNode->appInfo.fastTransData != NULL) {
            SoftBusFree((void *)destroyNode->appInfo.fastTransData);
        }
        (void)memset_s(destroyNode->appInfo.sessionKey, sizeof(destroyNode->appInfo.sessionKey), 0,
            sizeof(destroyNode->appInfo.sessionKey));
        SoftBusFree(destroyNode);
    }
    return;
}

void TransAuthDeathCallback(const char *pkgName, int32_t pid)
{
    if (g_authChannelList == NULL || pkgName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }

    char *anonymizePkgName = NULL;
    Anonymize(pkgName, &anonymizePkgName);
    TRANS_LOGI(TRANS_CTRL, "pkgName=%{public}s, pid=%{public}d.", AnonymizeWrapper(anonymizePkgName), pid);
    AnonymizeFree(anonymizePkgName);

    ListNode destroyList;
    ListInit(&destroyList);
    AuthChannelInfo *item = NULL;
    AuthChannelInfo *tmp = NULL;

    if (SoftBusMutexLock(&g_authChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, tmp, &g_authChannelList->list, AuthChannelInfo, node) {
        if ((strcmp(item->appInfo.myData.pkgName, pkgName) == 0) && (item->appInfo.myData.pid == pid)) {
            ListDelete(&(item->node));
            g_authChannelList->cnt--;
            ListAdd(&destroyList, &(item->node));
            TRANS_LOGE(TRANS_CTRL, "add to destroyList channelId=%{public}" PRId64, item->appInfo.myData.channelId);
            continue;
        }
    }
    (void)SoftBusMutexUnlock(&g_authChannelList->lock);
    TransAuthDestroyChannelList(&destroyList);
}
