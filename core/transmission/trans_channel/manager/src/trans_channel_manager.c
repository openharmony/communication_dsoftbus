/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "lnn_lane_qos.h"
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
#include "trans_tcp_direct_sessionconn.h"

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

static int32_t CopyAppInfoFromSessionParam(AppInfo* appInfo, const SessionParam* param)
{
    if (TransGetUidAndPid(param->sessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), param->groupId) != EOK) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), param->sessionName) != EOK) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->peerNetWorkId, sizeof(appInfo->peerNetWorkId), param->peerDeviceId) != EOK) {
        return SOFTBUS_ERR;
    }
    if (TransGetPkgNameBySessionName(param->sessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), param->peerSessionName) != 0) {
        return SOFTBUS_ERR;
    }
    if (LnnGetRemoteStrInfo(param->peerDeviceId, STRING_KEY_UUID,
        appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get remote node uuid err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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
    } else if (param->attr->dataType == TYPE_MESSAGE) {
        appInfo->businessType = BUSINESS_TYPE_MESSAGE;
    } else if (param->attr->dataType == TYPE_BYTES) {
        appInfo->businessType = BUSINESS_TYPE_BYTE;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    if (CopyAppInfoFromSessionParam(appInfo, param) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }

    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;

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
    LaneTransType transType = TransGetLaneTransTypeBySession(param);
    if (transType == LANE_T_BUTT) {
        return CHANNEL_TYPE_BUTT;
    }

    if (connInfo->type == LANE_BR || connInfo->type == LANE_BLE) {
        return CHANNEL_TYPE_PROXY;
    } else if (transType == LANE_T_FILE || transType == LANE_T_COMMON_VIDEO ||
        transType == LANE_T_RAW_STREAM) {
        return CHANNEL_TYPE_UDP;
    } else if ((transType == LANE_T_MSG) && (connInfo->type != LANE_P2P)) {
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
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));

    AppInfo *appInfo = GetAppInfo(param);
    if (appInfo == NULL) {
        goto EXIT_ERR;
    }

    if (TransGetLaneInfo(param, &connInfo, &laneId) != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_GET_LANE_INFO_ERR);
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "sessionName[%s], get laneId[%u], link type[%u].", param->sessionName, laneId, connInfo.type);

    if (TransGetConnectOptByConnInfo(&connInfo, &connOpt) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }

    transInfo->channelType = TransGetChannelType(param, &connInfo);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "lane[%u] get channel type[%u].", laneId, transInfo->channelType);

    if (TransOpenChannelProc((ChannelType)transInfo->channelType, appInfo, &connOpt,
        &(transInfo->channelId)) != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_CREATE_CHANNEL_ERR);
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
    SoftBusFree(appInfo);
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
    SoftBusFree(appInfo);
    return NULL;
}

int32_t TransOpenAuthChannel(const char *sessionName, const ConnectOption *connOpt)
{
    int32_t channelId = INVALID_CHANNEL_ID;
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1) || connOpt == NULL) {
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

static uint32_t MergeStatsInterval(const uint32_t *data, uint32_t left, uint32_t right)
{
    uint32_t result = 0;
    while (left <= right) {
        result += data[left];
        left++;
    }
    return result;
}

static void ConvertStreamStats(const StreamSendStats *src, FrameSendStats *dest)
{
    uint32_t *srcCostCnt = (uint32_t *)(src->costTimeStatsCnt);
    uint32_t *srcBitRate = (uint32_t *)(src->sendBitRateStatsCnt);
    uint32_t *destCostCnt = dest->costTimeStatsCnt;
    uint32_t *destBitRate = dest->sendBitRateStatsCnt;
    destCostCnt[FRAME_COST_TIME_SMALL] = srcCostCnt[FRAME_COST_LT10MS];
    destCostCnt[FRAME_COST_TIME_MEDIUM] = MergeStatsInterval(srcCostCnt, FRAME_COST_LT30MS, FRAME_COST_LT100MS);
    destCostCnt[FRAME_COST_TIME_LARGE] = srcCostCnt[FRAME_COST_LT120MS] + srcCostCnt[FRAME_COST_GE120MS];
    destBitRate[FRAME_BIT_RATE_SMALL] = srcBitRate[FRAME_BIT_RATE_LT3M];
    destBitRate[FRAME_BIT_RATE_MEDIUM] = MergeStatsInterval(srcBitRate, FRAME_BIT_RATE_LT6M, FRAME_BIT_RATE_LT30M);
    destBitRate[FRAME_BIT_RATE_LARGE] = srcBitRate[FRAME_BIT_RATE_GE30M];
}

int32_t TransStreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    (void)channelType;
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "streamStats data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneId;
    int32_t ret = TransGetLaneIdByChannelId(channelId, &laneId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get laneId fail, streamStatsInfo cannot be processed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "transStreamStats channelId:%d, laneId:0x%x", channelId, laneId);
    LaneIdStatsInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.laneId = laneId;
    info.statsType = LANE_T_COMMON_VIDEO;
    FrameSendStats *stats = &info.statsInfo.stream.frameStats;
    ConvertStreamStats(data, stats);
    LnnReportLaneIdStatsInfo(&info, 1); /* only report stream stats */
    return SOFTBUS_OK;
}

int32_t TransRequestQos(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    uint32_t laneId;
    int32_t ret = TransGetLaneIdByChannelId(channelId, &laneId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get laneId fail, transRequestQos cannot be processed");
        return SOFTBUS_ERR;
    }
    int32_t result = 0;
    if (quality == QOS_IMPROVE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans requestQos");
        ret = LnnRequestQosOptimization(&laneId, 1, &result, 1);
    } else if (quality == QOS_RECOVER) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans cancel Qos");
        LnnCancelQosOptimization(&laneId, 1);
        ret = SOFTBUS_OK;
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "requestQos quality[%d] invalid", quality);
        ret = SOFTBUS_ERR;
    }

    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "request Qos fail,type:%d, err:%d", quality, ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransRippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    (void)channelType;
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "rippleStats data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneId;
    int32_t ret = TransGetLaneIdByChannelId(channelId, &laneId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get laneId fail, streamStatsInfo cannot be processed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "transRippleStats channelId:%d, laneId:0x%x", channelId, laneId);
    LnnRippleData rptdata;
    (void)memset_s(&rptdata, sizeof(rptdata), 0, sizeof(rptdata));
    if (memcpy_s(&rptdata.stats, sizeof(rptdata.stats), data->stats, sizeof(data->stats)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy fail");
        return SOFTBUS_ERR;
    }
    LnnReportRippleData(laneId, &rptdata);
    return SOFTBUS_OK;
}

int32_t TransNotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    int32_t ret = SOFTBUS_ERR;
    ConnectOption connOpt;
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            ret = TransAuthGetConnOptionByChanId(channelId, &connOpt);
            break;
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyGetConnOptionByChanId(channelId, &connOpt);
            break;
        default:
            ret = SOFTBUS_ERR;
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "channel=%d, type=%d invalid.", channelId, channelType);
    }
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "channel=%d, type=%d,notfiy auth success error=%d.", channelId, channelType, ret);
        return ret;
    }
    return TransNotifyAuthDataSuccess(channelId, &connOpt);
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
            return TransSendAuthMsg(channelId, (char*)data, (int32_t)len);
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

int32_t TransGetAppInfoByChanId(int32_t channelId, int32_t channelType, AppInfo* appInfo)
{
    if (appInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch ((ChannelType)channelType) {
        case CHANNEL_TYPE_TCP_DIRECT:
            return TcpTranGetAppInfobyChannelId(channelId, appInfo);
        case CHANNEL_TYPE_PROXY:
            return TransProxyGetAppInfoByChanId(channelId, appInfo);
        case CHANNEL_TYPE_UDP:
            return TransGetUdpAppInfoByChannelId(channelId, appInfo);
        case CHANNEL_TYPE_AUTH:
            return TransAuthGetAppInfoByChanId(channelId, appInfo);
        default:
            return SOFTBUS_INVALID_PARAM;
    }
}

int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t* connId)
{
    if (channelType != CHANNEL_TYPE_PROXY) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "channelType:%d error", channelType);
        return SOFTBUS_ERR;
    }
    if (TransProxyGetConnIdByChanId(channelId, connId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get proxy connId, channelId: %d", channelId);
        return SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID;
    }
    return SOFTBUS_OK;
}