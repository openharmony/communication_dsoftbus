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
#include "softbus_proxychannel_listener.h"

#include <securec.h>

#include "bus_center_manager.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_network.h"
#include "softbus_proxychannel_session.h"
#include "softbus_utils.h"

static int32_t NotifyNormalChannelClosed(const char *pkgName, int32_t channelId)
{
    int32_t ret = GetClientProvideInterface()->onChannelClosed(pkgName, channelId);
    LOG_INFO("proxy channel close, channelId = %d, ret = %d", channelId, ret);
    return ret;
}

static int32_t NotifyNormalChannelOpenFailed(const char *pkgName, int32_t channelId)
{
    int32_t ret = GetClientProvideInterface()->onChannelOpenFailed(pkgName, channelId);
    LOG_INFO("proxy channel open fail, channelId = %d, ret = %d", channelId, ret);
    return ret;
}

static int32_t NotifyNormalChannelOpened(int32_t channelId, const AppInfo *appInfo, bool isServer)
{
    ChannelInfo info = {0};
    info.channelId = channelId;
    info.channelType = CHANNEL_TYPE_PROXY;
    info.isServer = isServer;
    info.isEnabled = true;
    info.groupId = (char*)appInfo->groupId;
    info.peerSessionName = (char*)appInfo->peerData.sessionName;
    info.peerDeviceId = (char*)appInfo->peerData.deviceId;
    info.peerPid = appInfo->peerData.pid;
    info.peerUid = appInfo->peerData.uid;
    char buf[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByUuid(appInfo->peerData.deviceId, buf, NETWORK_ID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get info networkId fail.");
        return SOFTBUS_ERR;
    }
    info.peerDeviceId = buf;

    ret = GetClientProvideInterface()->onChannelOpened(appInfo->myData.pkgName,
        appInfo->myData.sessionName, &info);
    LOG_INFO("proxy channel open, channelId = %d, ret = %d", channelId, ret);
    return ret;
}

int32_t OnProxyChannelOpened(int32_t channelId, const AppInfo *appInfo, unsigned char isServer)
{
    int32_t ret;

    if (appInfo == NULL) {
        LOG_ERR("invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LOG_INFO("proxy channel opened: channeld=%d, appType=%d, isServer=%d",
        channelId, appInfo->appType, isServer);

    switch (appInfo->appType) {
        case APP_TYPE_NORMAL:
            ret = NotifyNormalChannelOpened(channelId, appInfo, isServer);
            break;
        case APP_TYPE_AUTH:
            ret = SOFTBUS_ERR;
            break;
        case APP_TYPE_INNER:
            ret = NotifyNetworkingChannelOpened(channelId, appInfo, isServer);
            break;
        default:
            ret = SOFTBUS_ERR;
            break;
    }
    LOG_INFO("open ret %d", ret);
    return ret;
}

int32_t OnProxyChannelOpenFailed(int32_t channelId, const AppInfo *appInfo)
{
    int32_t ret = SOFTBUS_OK;

    if (appInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LOG_INFO("param: channelId=%d, appType=%d",
        channelId, appInfo->appType);

    switch (appInfo->appType) {
        case APP_TYPE_NORMAL:
            ret = NotifyNormalChannelOpenFailed(appInfo->myData.pkgName, channelId);
            break;
        case APP_TYPE_AUTH:
            ret = SOFTBUS_ERR;
            break;
        case APP_TYPE_INNER:
            NotifyNetworkingChannelOpenFailed(channelId, appInfo->peerData.deviceId);
            break;
        default:
            ret = SOFTBUS_ERR;
            break;
    }
    return ret;
}

int32_t OnProxyChannelClosed(int32_t channelId, const AppInfo *appInfo)
{
    if (appInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LOG_INFO("param: channelId=%d, appType=%d", channelId, appInfo->appType);

    int32_t ret = SOFTBUS_OK;
    switch (appInfo->appType) {
        case APP_TYPE_NORMAL:
            ret = NotifyNormalChannelClosed(appInfo->myData.pkgName, channelId);
            break;
        case APP_TYPE_AUTH:
            ret = SOFTBUS_ERR;
            break;
        case APP_TYPE_INNER:
            NotifyNetworkingChannelClosed(channelId);
            break;
        default:
            ret = SOFTBUS_ERR;
            break;
    }
    return ret;
}

int32_t OnProxyChannelMsgReceived(int32_t channelId, const AppInfo *appInfo,
                                  const char *data, uint32_t len)
{
    int32_t ret = SOFTBUS_OK;

    if (appInfo == NULL || data == NULL || len == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    switch (appInfo->appType) {
        case APP_TYPE_NORMAL:
            TransOnNormalMsgReceived(appInfo->myData.pkgName, channelId, data, len);
            break;
        case APP_TYPE_AUTH:
            ret = SOFTBUS_ERR;
            break;
        case APP_TYPE_INNER:
            NotifyNetworkingMsgReceived(channelId, data, len);
            break;
        default:
            ret = SOFTBUS_ERR;
            break;
    }
    return ret;
}

static int32_t TransProxyGetConnectOptionBr(const char *peerNetworkId, ConnectOption *opt)
{
    char brMac[BT_MAC_LEN] = {0};
    int ret;

    ret = LnnGetRemoteStrInfo(peerNetworkId, STRING_KEY_BT_MAC, brMac, sizeof(brMac));
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get momote node mac err %d", ret);
        return SOFTBUS_ERR;
    }

    opt->type = CONNECT_BR;
    if (strcpy_s(opt->info.brOption.brMac, sizeof(opt->info.brOption.brMac), brMac) != 0) {
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t TransProxyGetAppInfo(const char *sessionName, const char *peerNetworkId, AppInfo *appInfo)
{
    int ret;

    appInfo->appType = APP_TYPE_INNER;
    appInfo->myData.apiVersion = API_V2;
    ret = LnnGetLocalStrInfo(STRING_KEY_UUID, appInfo->myData.deviceId,
                             sizeof(appInfo->myData.deviceId));
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get local devid fail %d", ret);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), sessionName) != 0) {
        return SOFTBUS_ERR;
    }
    appInfo->peerData.apiVersion = API_V2;
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), sessionName) != 0) {
        return SOFTBUS_ERR;
    }

    ret = LnnGetRemoteStrInfo(peerNetworkId, STRING_KEY_UUID,
                              appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId));
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get remote node uuid err %d", ret);
        return SOFTBUS_GET_REMOTE_UUID_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransOpenNetWorkingChannel(const char *sessionName, const char *peerNetworkId)
{
    AppInfo appInfo;
    ConnectOption connOpt;
    int32_t channelId = INVALID_CHANNEL_ID;

    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerNetworkId, DEVICE_ID_SIZE_MAX)) {
        return channelId;
    }

    if (TransProxyGetConnectOptionBr(peerNetworkId, &connOpt) != SOFTBUS_OK) {
        LOG_ERR("networking get conn opthon fail");
        return channelId;
    }
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    if (TransProxyGetAppInfo(sessionName, peerNetworkId, &appInfo) != SOFTBUS_OK) {
        LOG_ERR("networking get app info fail");
        return channelId;
    }

    if (TransProxyOpenProxyChannel(&appInfo, &connOpt, &channelId) != SOFTBUS_OK) {
        LOG_ERR("networking open channel fail");
        channelId = INVALID_CHANNEL_ID;
    }
    return channelId;
}

int32_t TransSendNetworkingMessage(int32_t channelId, const char *data, int32_t dataLen, int32_t priority)
{
    return TransProxySendMsg(channelId, data, dataLen, priority);
}

int32_t TransCloseNetWorkingChannel(int32_t channelId)
{
    return TransProxyCloseProxyChannel(channelId);
}
