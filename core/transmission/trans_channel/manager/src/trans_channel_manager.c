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
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_session.h"
#include "softbus_qos.h"
#include "softbus_utils.h"
#include "trans_auth_manager.h"
#include "trans_channel_callback.h"
#include "trans_lane_manager.h"
#include "trans_lane_pending_ctl.h"
#include "trans_link_listener.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_manager.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"
#include "softbus_hisysevt_transreporter.h"

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

    if (TransReqLanePendingInit() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    ReqLinkListener();

    return SOFTBUS_OK;
}

void TransChannelDeinit(void)
{
    TransLaneMgrDeinit();
    TransAuthDeinit();
    TransProxyManagerDeinit();
    TransTcpDirectDeinit();
    TransUdpChannelDeinit();
    TransReqLanePendingDeinit();
}

static AppInfo *GetAppInfo(const SessionParam *param)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetAppInfo");
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return NULL;
    }
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
    if (param->attr->dataType == TYPE_STREAM) {
        appInfo->businessType = BUSINESS_TYPE_STREAM;
        appInfo->streamType = (StreamType)param->attr->attr.streamAttr.streamType;
    } else if (param->attr->dataType == TYPE_FILE) {
        appInfo->businessType = BUSINESS_TYPE_FILE;
    }
    if (TransGetUidAndPid(param->sessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), param->groupId) != EOK) {
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), param->sessionName) != EOK) {
        goto EXIT_ERR;
    }
    if (TransGetPkgNameBySessionName(param->sessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }

    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), param->peerSessionName) != 0) {
        goto EXIT_ERR;
    }
    if (LnnGetRemoteStrInfo(param->peerDeviceId, STRING_KEY_UUID,
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

static ChannelType TransGetChannelType(const SessionParam *param, const LaneConnInfo *connInfo)
{
    LaneTransType transType = TransGetLaneTransTypeBySession((SessionType)param->attr->dataType);
    if (transType == LANE_T_BUTT) {
        return CHANNEL_TYPE_BUTT;
    }

    if (connInfo->type == LANE_BR || connInfo->type == LANE_BLE) {
        return CHANNEL_TYPE_PROXY;
    } else if (transType == LANE_T_FILE || transType == LANE_T_STREAM) {
        return CHANNEL_TYPE_UDP;
    } else if (transType == LANE_T_MSG) {
        return CHANNEL_TYPE_PROXY;
    }
    return CHANNEL_TYPE_TCP_DIRECT;
}

static int32_t TransOpenChannelProc(ChannelType type, AppInfo *appInfo, const ConnectOption *connOpt,
    int32_t *channelId)
{
    if (type == CHANNEL_TYPE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "open invalid channel type.");
        return SOFTBUS_ERR;
    }
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
        if (TransOpenDirectChannel(appInfo, connOpt, channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open direct channel err");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t TransOpenChannel(const SessionParam *param, TransInfo *transInfo)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server TransOpenChannel");
    transInfo->channelId = INVALID_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_BUTT;
    LaneConnInfo connInfo;
    uint32_t laneId = 0;
    AppInfo *appInfo = NULL;
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));

    appInfo = GetAppInfo(param);
    if (appInfo == NULL) {
        goto EXIT_ERR;
    }

    if (TransGetLaneInfo(param, &connInfo, &laneId) != SOFTBUS_OK) {
        if (SoftbusReportTransErrorEvt(SOFTBUS_TRANS_GET_LANE_INFO_ERR) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SOFTBUS Write Get Lane Fault Evt Failed!");
        }
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get laneId[%u], link type[%u].", laneId, connInfo.type);

    if (TransGetConnectOptByConnInfo(&connInfo, &connOpt) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }

    transInfo->channelType = TransGetChannelType(param, &connInfo);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "lane[%u] get channel type[%u].", laneId, transInfo->channelType);

    if (TransOpenChannelProc((ChannelType)transInfo->channelType, appInfo, &connOpt,
        &(transInfo->channelId)) != SOFTBUS_OK) {
        if (SoftbusReportTransErrorEvt(SOFTBUS_TRANS_CREATE_CHANNEL_ERR) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SOFTBUS Write Get Lane Fault Evt Failed!");
        }
        goto EXIT_ERR;
    }

    if (TransLaneMgrAddLane(transInfo->channelId, transInfo->channelType,
        &connInfo, laneId, appInfo->myData.pkgName) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }

    SoftBusFree(appInfo);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server TransOpenChannel ok: channelId=%d, channelType=%d",
        transInfo->channelId, transInfo->channelType);
    return SOFTBUS_OK;
EXIT_ERR:
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    if (laneId != 0) {
        LnnFreeLane(laneId);
    }
    if (transInfo->channelId != INVALID_CHANNEL_ID) {
        (void)TransCloseChannel(transInfo->channelId, transInfo->channelType);
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server TransOpenChannel err");
    return INVALID_CHANNEL_ID;
}

static AppInfo *GetAuthAppInfo(const char *mySessionName)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetAuthAppInfo");
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return NULL;
    }
    appInfo->appType = APP_TYPE_AUTH;
    appInfo->myData.apiVersion = API_V2;
    if (TransGetUidAndPid(mySessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo GetUidAndPid failed");
        goto EXIT_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo get deviceId failed");
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), mySessionName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo strcpy_s mySessionName failed");
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), mySessionName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo strcpy_s peerSessionName failed");
        goto EXIT_ERR;
    }
    if (TransGetPkgNameBySessionName(mySessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo get PkgName failed");
        goto EXIT_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetAuthAppInfo ok");
    return appInfo;
EXIT_ERR:
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    return NULL;
}

int32_t TransOpenAuthChannel(const char *sessionName, const ConnectOption *connOpt)
{
    int32_t channelId = INVALID_CHANNEL_ID;
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX) || connOpt == NULL) {
        return channelId;
    }

    if (connOpt->type == CONNECT_TCP) {
        if (TransOpenAuthMsgChannel(sessionName, connOpt, &channelId) != SOFTBUS_OK) {
            return INVALID_CHANNEL_ID;
        }
    } else if (connOpt->type == CONNECT_BR || connOpt->type == CONNECT_BLE) {
        AppInfo *appInfo = GetAuthAppInfo(sessionName);
        if (appInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo failed");
            return INVALID_CHANNEL_ID;
        }
        if (TransProxyOpenProxyChannel(appInfo, connOpt, &channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransOpenAuthChannel proxy channel err");
            SoftBusFree(appInfo);
            return INVALID_CHANNEL_ID;
        }
        SoftBusFree(appInfo);
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
            (void)NotifyQosChannelClosed(channelId, channelType);
            (void)TransLaneMgrDelLane(channelId, channelType);
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
            return TransSendAuthMsg(channelId, data, (int32_t)len);
        case CHANNEL_TYPE_PROXY:
            return TransProxyPostSessionData(channelId, (unsigned char*)data, len, (SessionPktType)msgType);
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send msg: id=%d invalid type=%d", channelId, channelType);
            return SOFTBUS_TRANS_CHANNEL_TYPE_INVALID;
    }
}

void TransChannelDeathCallback(const char *pkgName)
{
    TransProxyDeathCallback(pkgName);
    TransTdcDeathCallback(pkgName);
    TransLaneMgrDeathCallback(pkgName);
    TransUdpDeathCallback(pkgName);
}

int32_t TransGetNameByChanId(const TransInfo *info, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionNameLen)
{
    if (info == NULL || pkgName == NULL || sessionName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch ((ChannelType)info->channelType) {
        case CHANNEL_TYPE_PROXY:
            return TransProxyGetNameByChanId(info->channelId, pkgName, sessionName, pkgLen, sessionNameLen);
        case CHANNEL_TYPE_UDP:
            return TransUdpGetNameByChanId(info->channelId, pkgName, sessionName, pkgLen, sessionNameLen);
        case CHANNEL_TYPE_AUTH:
            return TransAuthGetNameByChanId(info->channelId, pkgName, sessionName, pkgLen, sessionNameLen);
        default:
            return SOFTBUS_INVALID_PARAM;
    }
}