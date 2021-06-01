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

#include "trans_channel_manager.h"
#include "securec.h"

#include "bus_center_manager.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_permission.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_session.h"
#include "softbus_utils.h"
#ifndef SOFTBUS_WATCH
#include "trans_tcp_direct_manager.h"
#endif
#define TCP_PORT_LEN 10

int GetConnectOptionTcp(const char *peerDeviceId, ConnectOption *opt)
{
    opt->type = CONNECT_TCP;

    char ip[IP_MAX_LEN] = {0};
    if (LnnGetRemoteStrInfo(peerDeviceId, STRING_KEY_WLAN_IP, ip, sizeof(ip)) != 0) {
        LOG_ERR("get remote node ip err");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(opt->info.ipOption.ip, sizeof(opt->info.ipOption.ip), ip) != 0) {
        return SOFTBUS_ERR;
    }

    int port = 0;
    if (LnnGetRemoteNumInfo(peerDeviceId, NUM_KEY_SESSION_PORT, &port) != 0) {
        LOG_ERR("get momote node ip err");
        return SOFTBUS_ERR;
    }
    opt->info.ipOption.port = port;

    return SOFTBUS_OK;
}

static ChannelType TransGetChannelType(void)
{
#ifdef SOFTBUS_WATCH
    return CHANNEL_TYPE_PROXY;
#else
    return CHANNEL_TYPE_TCP_DIRECT;
#endif
}

int32_t TransChannelInit(void)
{
    int type = TransGetChannelType();
    switch (type) {
        case CHANNEL_TYPE_PROXY:
            if (TransProxyManagerInit() != SOFTBUS_OK) {
                return SOFTBUS_ERR;
            }
            break;
#ifndef SOFTBUS_WATCH
        case CHANNEL_TYPE_TCP_DIRECT:
            if (TransTcpDirectInit() != SOFTBUS_OK) {
                return SOFTBUS_ERR;
            }
            break;
#endif
        default:
            break;
    }
    return SOFTBUS_OK;
}

void TransChannelDeinit(void)
{
    int type = TransGetChannelType();
    switch (type) {
        case CHANNEL_TYPE_PROXY:
            TransProxyManagerDeinit();
            break;
#ifndef SOFTBUS_WATCH
        case CHANNEL_TYPE_TCP_DIRECT:
            TransTcpDirectDeinit();
            break;
#endif
        default:
            break;
    }
}

static int GetConnectOptionBr(const char *peerDeviceId, ConnectOption *opt)
{
    opt->type = CONNECT_BR;
    char brMac[BT_MAC_LEN] = {0};
    if (LnnGetRemoteStrInfo(peerDeviceId, STRING_KEY_BT_MAC, brMac, sizeof(brMac)) != 0) {
        LOG_ERR("get remote node mac err");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(opt->info.brOption.brMac, sizeof(opt->info.brOption.brMac), brMac) != 0) {
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static AppInfo *GetAppInfo(const char *mySessionName, const char *peerSessionName, const char *peerDeviceId,
    const char *groupId, int32_t flags)
{
    (void)flags;
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return NULL;
    }
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;

    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != 0) {
        goto EXIT_ERR;
    }

    if (strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), groupId) != 0) {
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), mySessionName) != 0) {
        goto EXIT_ERR;
    }

    appInfo->peerData.apiVersion = API_V2;
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), peerSessionName) != 0) {
        goto EXIT_ERR;
    }
    if (LnnGetRemoteStrInfo(peerDeviceId, STRING_KEY_UUID,
        appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId)) != SOFTBUS_OK) {
        LOG_ERR("get remote node uuid err");
        goto EXIT_ERR;
    }

    return appInfo;
EXIT_ERR:
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    return NULL;
}

int32_t TransOpenChannel(const char *mySessionName, const char *peerSessionName, const char *peerDeviceId,
    const char *groupId, int32_t flags)
{
    int32_t channelId = INVALID_CHANNEL_ID;
    if (!IsValidString(mySessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerSessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerDeviceId, DEVICE_ID_SIZE_MAX) ||
        !IsValidString(groupId, GROUP_ID_SIZE_MAX)) {
        return channelId;
    }

    ConnectOption connOpt = {0};
    AppInfo *appInfo = GetAppInfo(mySessionName, peerSessionName, peerDeviceId, groupId, flags);
    if (appInfo == NULL) {
        LOG_ERR("get app info err");
        return channelId;
    }

    int type = TransGetChannelType();
    switch (type) {
        case CHANNEL_TYPE_PROXY:
            if (GetConnectOptionBr(peerDeviceId, &connOpt) != SOFTBUS_OK) {
                LOG_ERR("get connection opt err");
                break;
            }
            if (TransProxyOpenProxyChannel(appInfo, &connOpt, &channelId) != SOFTBUS_OK) {
                LOG_ERR("open proxy channel err");
                channelId = INVALID_CHANNEL_ID;
            }
            break;
#ifndef SOFTBUS_WATCH
        case CHANNEL_TYPE_TCP_DIRECT:
            if (GetConnectOptionTcp(peerDeviceId, &connOpt) != SOFTBUS_OK) {
                LOG_ERR("get connection opt err");
                break;
            }

            if (TransOpenTcpDirectChannel(appInfo, &connOpt, &channelId) != SOFTBUS_OK) {
                LOG_ERR("open direct channel err");
                channelId = INVALID_CHANNEL_ID;
            }
            break;
#endif
        default:
            break;
    }
    SoftBusFree(appInfo);
    return channelId;
}

int32_t TransCloseChannel(int32_t channelId)
{
    char pkgName[PKG_NAME_SIZE_MAX];
    char sessionName[SESSION_NAME_SIZE_MAX];
    if (TransProxyGetNameByChanId(channelId, pkgName, sessionName,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        LOG_ERR("Trans close channel get pkgName by chanId failed");
        return SOFTBUS_ERR;
    }
    if (CheckTransPermission(sessionName, pkgName, ACTION_OPEN) < SOFTBUS_OK) {
        LOG_ERR("Trans close channel no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return TransProxyCloseProxyChannel(channelId);
}

int32_t TransSendMsg(int32_t channelId, const void *data, uint32_t len, int32_t msgType)
{
    char pkgName[PKG_NAME_SIZE_MAX];
    char sessionName[SESSION_NAME_SIZE_MAX];
    if (TransProxyGetNameByChanId(channelId, pkgName, sessionName,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        LOG_ERR("Trans send msg get pkgName by chanId failed");
        return SOFTBUS_ERR;
    }
    if (CheckTransPermission(sessionName, pkgName, 0) < SOFTBUS_OK) {
        LOG_ERR("Trans send msg no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return TransProxyPostSessionData(channelId, (uint8_t*)data, len, msgType);
}

