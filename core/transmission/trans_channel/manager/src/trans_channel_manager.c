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

#include <securec.h>

#include "bus_center_manager.h"
#include "lnn_lane_manager.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_session.h"
#include "softbus_utils.h"
#include "trans_auth_manager.h"
#include "trans_channel_callback.h"
#include "trans_lane_manager.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_manager.h"
#include "trans_udp_negotiation.h"

int32_t TransChannelInit(void)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    if (cb == NULL) {
        return SOFTBUS_ERR;
    }

    if (TransLaneMgrInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane manager init failed.");
        return SOFTBUS_ERR;
    }

    if (TransAuthInit(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (TransProxyManagerInit(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (TransTcpDirectInit(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (TransUdpChannelInit(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

void TransChannelDeinit(void)
{
    TransLaneMgrDeinit();
    TransAuthDeinit();
    TransProxyManagerDeinit();
    TransTcpDirectDeinit();
    TransUdpChannelDeinit();
}

static AppInfo *GetAppInfo(const char *mySessionName, const char *peerSessionName, const char *peerDeviceId,
    const char *groupId, int32_t flags)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetAppInfo");
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return NULL;
    }
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
    if (flags == TYPE_STREAM) {
        appInfo->businessType = BUSINESS_TYPE_STREAM;
        appInfo->streamType = RAW_STREAM;
    } else if (flags == TYPE_FILE) {
        appInfo->businessType = BUSINESS_TYPE_FILE;
    }
    if (TransGetUidAndPid(mySessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), groupId) != EOK) {
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), mySessionName) != EOK) {
        goto EXIT_ERR;
    }
    if (TransGetPkgNameBySessionName(mySessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }

    appInfo->peerData.apiVersion = API_V2;
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), peerSessionName) != 0) {
        goto EXIT_ERR;
    }
    if (LnnGetRemoteStrInfo(peerDeviceId, STRING_KEY_UUID,
        appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get remote node uuid err");
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetAppInfo ok");
    return appInfo;
EXIT_ERR:
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    return NULL;
}

static LnnLaneProperty TransGetLnnLaneProperty(SessionType type)
{
    switch (type) {
        case TYPE_MESSAGE:
            return LNN_MESSAGE_LANE;
        case TYPE_BYTES:
            return LNN_BYTES_LANE;
        case TYPE_FILE:
            return LNN_FILE_LANE;
        case TYPE_STREAM:
            return LNN_STREAM_LANE;
        default:
            return LNN_LANE_PROPERTY_BUTT;
    }
}

static int32_t TransGetLaneInfo(int32_t flags, const char *peerDeviceId,
    LnnLanesObject **lanesObject, const LnnLaneInfo **laneInfo)
{
    LnnLaneProperty laneProperty = TransGetLnnLaneProperty((SessionType)flags);
    if (laneProperty == LNN_LANE_PROPERTY_BUTT) {
        return SOFTBUS_TRANS_GET_LANE_INFO_ERR;
    }
    LnnLanesObject *object = LnnRequestLanesObject(peerDeviceId, laneProperty, 1);
    if (object == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get lne obj err");
        return SOFTBUS_TRANS_GET_LANE_INFO_ERR;
    }
    int32_t laneIndex = 0;
    int32_t laneId = LnnGetLaneId(object, laneIndex);
    const LnnLaneInfo *info = LnnGetConnection(laneId);
    if (info == NULL) {
        LnnReleaseLanesObject(object);
        return SOFTBUS_TRANS_GET_LANE_INFO_ERR;
    }

    *lanesObject = object;
    *laneInfo = info;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get lane info ok: flags=%d", flags);
    return SOFTBUS_OK;
}

static int32_t TransGetConnectOption(const ConnectionAddr *connAddr, ConnectOption *connOpt)
{
    ConnectionAddrType type = connAddr->type;
    if (type == CONNECTION_ADDR_WLAN || type == CONNECTION_ADDR_ETH) {
        connOpt->type = CONNECT_TCP;
        connOpt->info.ipOption.port = (int32_t)connAddr->info.ip.port;
        if (strcpy_s(connOpt->info.ipOption.ip, sizeof(connOpt->info.ipOption.ip), connAddr->info.ip.ip) != EOK) {
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    } else if (type == CONNECTION_ADDR_BR) {
        connOpt->type = CONNECT_BR;
        if (strcpy_s(connOpt->info.brOption.brMac, sizeof(connOpt->info.brOption.brMac),
            connAddr->info.br.brMac) != EOK) {
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get conn opt err: type=%d", type);
        return SOFTBUS_ERR;
    }
}

static ChannelType TransGetChannelType(const LnnLaneInfo *info)
{
    if (info->isSupportUdp == true) {
        return CHANNEL_TYPE_UDP;
    } else if (info->isProxy == true) {
        return CHANNEL_TYPE_PROXY;
    } else {
        return CHANNEL_TYPE_TCP_DIRECT;
    }
}

static int32_t TransOpenChannelProc(ChannelType type, AppInfo *appInfo, const ConnectOption *connOpt,
    int32_t *channelId)
{
    if (type == CHANNEL_TYPE_UDP) {
        if (TransOpenUdpChannel(appInfo, connOpt, channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "open udp channel err");
            return SOFTBUS_ERR;
        }
    } else if (type == CHANNEL_TYPE_PROXY) {
        if (TransProxyOpenProxyChannel(appInfo, connOpt, channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open proxy channel err");
            return SOFTBUS_ERR;
        }
    } else {
        if (TransOpenTcpDirectChannel(appInfo, connOpt, channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open direct channel err");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t TransOpenChannel(const SessionParam* param, TransInfo* transInfo)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server TransOpenChannel");
    transInfo->channelId = INVALID_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_BUTT;
    LnnLanesObject *object = NULL;
    const LnnLaneInfo *info = NULL;
    AppInfo *appInfo = NULL;
    ConnectOption connOpt = {0};

    if (!IsValidString(param->sessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(param->peerDeviceId, DEVICE_ID_SIZE_MAX) ||
        !IsValidString(param->peerSessionName, SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (param->groupId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    appInfo = GetAppInfo(param->sessionName, param->peerSessionName, param->peerDeviceId, param->groupId,
        param->attr->dataType);
    if (appInfo == NULL) {
        goto EXIT_ERR;
    }

    if (TransGetLaneInfo(param->attr->dataType, param->peerDeviceId, &object, &info) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "lane info: isSupportUdp=%d, isProxy=%d, connType=%d",
        info->isSupportUdp, info->isProxy, info->conOption.type);

    if (TransGetConnectOption(&info->conOption, &connOpt) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }

    transInfo->channelType = TransGetChannelType(info);
    if (TransOpenChannelProc(transInfo->channelType, appInfo, &connOpt, &(transInfo->channelId)) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }

    LnnReleaseLanesObject(object);
    SoftBusFree(appInfo);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server TransOpenChannel ok: channelId=%d, channelType=%d",
        transInfo->channelId, transInfo->channelType);
    return SOFTBUS_OK;
EXIT_ERR:
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    if (object != NULL) {
        LnnReleaseLanesObject(object);
    }
    if (transInfo->channelId != INVALID_CHANNEL_ID) {
        (void)TransCloseChannel(transInfo->channelId, transInfo->channelType);
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server TransOpenChannel err");
    return INVALID_CHANNEL_ID;
}

int32_t TransOpenAuthChannel(const char *sessionName, const ConnectOption *connOpt)
{
    int32_t channelId = INVALID_CHANNEL_ID;
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX) || connOpt == NULL) {
        return channelId;
    }
    if (connOpt->type != CONNECT_TCP) {
        return channelId;
    }
    if (TransOpenAuthMsgChannel(sessionName, connOpt, &channelId) != SOFTBUS_OK) {
        return INVALID_CHANNEL_ID;
    }
    return channelId;
}

int32_t TransNotifyAuthSuccess(int32_t channelId)
{
    return TransNotifyAuthDataSuccess(channelId);
}

int32_t TransCloseChannel(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "close channel: id=%d, type=%d", channelId, channelType);
    switch (channelType) {
        case CHANNEL_TYPE_PROXY:
            (void)TransLaneMgrDelLane(channelId, channelType);
            return TransProxyCloseProxyChannel(channelId);
        case CHANNEL_TYPE_TCP_DIRECT:
            (void)TransLaneMgrDelLane(channelId, channelType);
            return SOFTBUS_OK;
        case CHANNEL_TYPE_UDP:
            return TransCloseUdpChannel(channelId);
        case CHANNEL_TYPE_AUTH:
            return TransCloseAuthChannel(channelId);
        default:
            break;
    }
    return SOFTBUS_ERR;
}

int32_t TransSendMsg(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send msg: id=%d, type=%d", channelId, channelType);
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            return TransSendAuthMsg(channelId, data, len);
        case CHANNEL_TYPE_PROXY:
            return TransProxyPostSessionData(channelId, (unsigned char*)data, len, msgType);
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send msg: id=%d invalid type=%d", channelId, channelType);
            return SOFTBUS_ERR;
    }
}

void TransChannelDeathCallback(const char *pkgName)
{
    TransProxyDeathCallback(pkgName);
    TransTdcDeathCallback(pkgName);
}
