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

#include "trans_channel_manager.h"

#include <securec.h>

#include "access_control.h"
#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_qos.h"
#include "lnn_network_manager.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_session.h"
#include "softbus_qos.h"
#include "softbus_utils.h"
#include "trans_auth_manager.h"
#include "trans_channel_callback.h"
#include "trans_channel_common.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_lane_pending_ctl.h"
#include "trans_link_listener.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"

#define MIGRATE_ENABLE 2
#define MIGRATE_SUPPORTED 1
#define MAX_PROXY_CHANNEL_ID 0x00000800
#define MAX_TDC_CHANNEL_ID 0x7FFFFFFF
#define MIN_FD_ID 1025
#define MAX_FD_ID 2048
#define MAX_PROXY_CHANNEL_ID_COUNT 1024
#define ID_NOT_USED 0
#define ID_USED 1UL
#define BIT_NUM 8

static int32_t g_allocTdcChannelId = MAX_PROXY_CHANNEL_ID;
static SoftBusMutex g_myIdLock;
static unsigned long g_proxyChanIdBits[MAX_PROXY_CHANNEL_ID_COUNT / BIT_NUM / sizeof(long)] = {0};
static uint32_t g_proxyIdMark = 0;
static uint32_t g_channelIdCount = 0;

static int32_t GenerateTdcChannelId()
{
    int32_t channelId;
    if (SoftBusMutexLock(&g_myIdLock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    channelId = g_allocTdcChannelId++;
    if (g_allocTdcChannelId >= MAX_TDC_CHANNEL_ID) {
        g_allocTdcChannelId = MAX_PROXY_CHANNEL_ID;
    }
    SoftBusMutexUnlock(&g_myIdLock);
    return channelId;
}

static int32_t GenerateProxyChannelId()
{
    if (SoftBusMutexLock(&g_myIdLock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    if (g_channelIdCount >= MAX_PROXY_CHANNEL_ID_COUNT) {
        TRANS_LOGE(TRANS_CTRL, "No more channel Ids(1024) can be applied");
        SoftBusMutexUnlock(&g_myIdLock);
        return INVALID_CHANNEL_ID;
    }

    for (uint32_t id = g_proxyIdMark + 1; id != g_proxyIdMark; id++) {
        id = id % MAX_PROXY_CHANNEL_ID_COUNT;
        uint32_t index = id / (BIT_NUM * sizeof(long));
        uint32_t bit = id % (BIT_NUM * sizeof(long));
        if ((g_proxyChanIdBits[index] & (ID_USED << bit)) == ID_NOT_USED) {
            g_proxyChanIdBits[index] |= (ID_USED << bit);
            g_proxyIdMark = id;
            g_channelIdCount++;
            SoftBusMutexUnlock(&g_myIdLock);
            return (int32_t)id + MIN_FD_ID;
        }
    }
    SoftBusMutexUnlock(&g_myIdLock);
    return INVALID_CHANNEL_ID;
}

void ReleaseProxyChannelId(int32_t channelId)
{
    if (channelId < MIN_FD_ID || channelId > MAX_FD_ID) {
        return;
    }
    if (SoftBusMutexLock(&g_myIdLock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail");
        return;
    }
    if (g_channelIdCount >= ID_USED) {
        g_channelIdCount--;
    } else {
        TRANS_LOGE(TRANS_CTRL, "g_channelIdCount error");
    }
    uint32_t id = (uint32_t)channelId - MIN_FD_ID;
    uint32_t dex = id / (8 * sizeof(long));
    uint32_t bit = id % (8 * sizeof(long));
    g_proxyChanIdBits[dex] &= (~(ID_USED << bit));
    SoftBusMutexUnlock(&g_myIdLock);
}

int32_t GenerateChannelId(bool isTdcChannel)
{
    return isTdcChannel ? GenerateTdcChannelId() : GenerateProxyChannelId();
}

int32_t TransChannelInit(void)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    if (cb == NULL) {
        TRANS_LOGE(TRANS_INIT, "cd is null.");
        return SOFTBUS_ERR;
    }

    if (TransLaneMgrInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager init failed.");
        return SOFTBUS_ERR;
    }

    if (TransSocketLaneMgrInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans socket lane manager init failed.");
        return SOFTBUS_ERR;
    }

    if (TransAuthInit(cb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans auth init failed.");
        return SOFTBUS_ERR;
    }

    if (TransProxyManagerInit(cb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans proxy manager init failed.");
        return SOFTBUS_ERR;
    }

    if (TransTcpDirectInit(cb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans tcp direct init failed.");
        return SOFTBUS_ERR;
    }

    if (TransUdpChannelInit(cb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans udp channel init failed.");
        return SOFTBUS_ERR;
    }

    if (TransReqLanePendingInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans req lane pending init failed.");
        return SOFTBUS_ERR;
    }

    if (TransAsyncReqLanePendingInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans async req lane pending init failed.");
        return SOFTBUS_ERR;
    }

    ReqLinkListener();

    if (SoftBusMutexInit(&g_myIdLock, NULL) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init lock failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

void TransChannelDeinit(void)
{
    TransLaneMgrDeinit();
    TransSocketLaneMgrDeinit();
    TransAuthDeinit();
    TransProxyManagerDeinit();
    TransTcpDirectDeinit();
    TransUdpChannelDeinit();
    TransReqLanePendingDeinit();
    TransAsyncReqLanePendingDeinit();
    SoftBusMutexDestroy(&g_myIdLock);
}

static void TransSetFirstTokenInfo(AppInfo *appInfo, TransEventExtra *event)
{
    event->firstTokenId = TransACLGetFirstTokenID();
    if (event->firstTokenId == TOKENID_NOT_SET) {
        event->firstTokenId = appInfo->callingTokenId;
    }
    TransGetTokenInfo(event->firstTokenId, appInfo->tokenName, sizeof(appInfo->tokenName), &event->firstTokenType);
    event->firstTokenName = appInfo->tokenName;
}

int32_t TransOpenChannel(const SessionParam *param, TransInfo *transInfo)
{
    if (param == NULL || transInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_CTRL, "server TransOpenChannel");
    int32_t ret = INVALID_CHANNEL_ID;
    uint32_t laneHandle = INVALID_LANE_REQ_ID;
    char *tmpName = NULL;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    ret = TransAddSocketChannelInfo(
        param->sessionName, param->sessionId, INVALID_CHANNEL_ID, CHANNEL_TYPE_UNDEFINED, CORE_SESSION_STATE_INIT);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "Add socket channel record failed.");
    if (param->isAsync) {
        uint32_t callingTokenId = TransACLGetCallingTokenID();
        ret = TransAsyncGetLaneInfo(param, &laneHandle, callingTokenId);
        if (ret != SOFTBUS_OK) {
            Anonymize(param->sessionName, &tmpName);
            TRANS_LOGE(TRANS_CTRL, "Async get Lane failed, sessionName=%{public}s, sessionId=%{public}d",
                tmpName, param->sessionId);
            AnonymizeFree(tmpName);
            if (ret != SOFTBUS_TRANS_STOP_BIND_BY_CANCEL) {
                TransFreeLane(laneHandle, param->isQosLane);
            }
            (void)TransDeleteSocketChannelInfoBySession(param->sessionName, param->sessionId);
        }
        return ret;
    }
    int64_t timeStart = GetSoftbusRecordTimeMillis();
    transInfo->channelId = INVALID_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_BUTT;
    LaneConnInfo connInfo;
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    AppInfo *appInfo = TransCommonGetAppInfo(param);
    TRANS_CHECK_AND_RETURN_RET_LOGW(!(appInfo == NULL), INVALID_CHANNEL_ID, TRANS_CTRL, "GetAppInfo is null.");
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t peerRet = LnnGetRemoteNodeInfoById(appInfo->peerNetWorkId, CATEGORY_NETWORK_ID, &nodeInfo);
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    TransBuildTransOpenChannelStartEvent(&extra, appInfo, &nodeInfo, peerRet);
    TransSetFirstTokenInfo(appInfo, &extra);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_START, extra);
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    if (ret != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_GET_LANE_INFO_ERR);
        goto EXIT_ERR;
    }
    Anonymize(param->sessionName, &tmpName);
    TRANS_LOGI(TRANS_CTRL,
        "sessionName=%{public}s, laneHandle=%{public}u, linkType=%{public}u.",
        tmpName, laneHandle, connInfo.type);
    AnonymizeFree(tmpName);
    ret = TransGetConnectOptByConnInfo(&connInfo, &connOpt);
    if (ret != SOFTBUS_OK) {
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, connInfo.type,
            SOFTBUS_EVT_OPEN_SESSION_FAIL, GetSoftbusRecordTimeMillis() - timeStart);
        goto EXIT_ERR;
    }
    appInfo->connectType = connOpt.type;
    extra.linkType = connOpt.type;
    FillAppInfo(appInfo, param, transInfo, &connInfo);
    TransOpenChannelSetModule(transInfo->channelType, &connOpt);
    TRANS_LOGI(TRANS_CTRL, "laneHandle=%{public}u, channelType=%{public}u", laneHandle, transInfo->channelType);
    TransGetSocketChannelStateBySession(param->sessionName, param->sessionId, &state);
    if (state == CORE_SESSION_STATE_CANCELLING) {
        goto EXIT_CANCEL;
    }
    TransSetSocketChannelStateBySession(param->sessionName, param->sessionId, CORE_SESSION_STATE_LAN_COMPLETE);
    ret = TransOpenChannelProc((ChannelType)transInfo->channelType, appInfo, &connOpt,
        &(transInfo->channelId));
    if (ret != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_CREATE_CHANNEL_ERR);
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName,
            appInfo->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, GetSoftbusRecordTimeMillis() - timeStart);
        goto EXIT_ERR;
    }
    TransUpdateSocketChannelInfoBySession(
        param->sessionName, param->sessionId, transInfo->channelId, transInfo->channelType);
    TransSetSocketChannelStateByChannel(
        transInfo->channelId, transInfo->channelType, CORE_SESSION_STATE_CHANNEL_OPENED);
    if (((ChannelType)transInfo->channelType == CHANNEL_TYPE_TCP_DIRECT) && (connOpt.type != CONNECT_P2P)) {
        TransFreeLane(laneHandle, param->isQosLane);
    } else if (TransLaneMgrAddLane(transInfo->channelId, transInfo->channelType, &connInfo,
        laneHandle, param->isQosLane, &appInfo->myData) != SOFTBUS_OK) {
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName,
            appInfo->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, GetSoftbusRecordTimeMillis() - timeStart);
        TransCloseChannel(NULL, transInfo->channelId, transInfo->channelType);
        goto EXIT_ERR;
    }
    TransFreeAppInfo(appInfo);
    TRANS_LOGI(TRANS_CTRL, "server TransOpenChannel ok: channelId=%{public}d, channelType=%{public}d",
        transInfo->channelId, transInfo->channelType);
    return SOFTBUS_OK;
EXIT_ERR:
    TransBuildTransOpenChannelEndEvent(&extra, transInfo, timeStart, ret);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    TransAlarmExtra extraAlarm;
    TransBuildTransAlarmEvent(&extraAlarm, appInfo, ret);
    TRANS_ALARM(OPEN_SESSION_FAIL_ALARM, CONTROL_ALARM_TYPE, extraAlarm);
    TransFreeAppInfo(appInfo);
    if (ret != SOFTBUS_TRANS_STOP_BIND_BY_CANCEL) {
        TransFreeLane(laneHandle, param->isQosLane);
    }
    (void)TransDeleteSocketChannelInfoBySession(param->sessionName, param->sessionId);
    TRANS_LOGE(TRANS_SVC, "server TransOpenChannel err, ret=%{public}d", ret);
    return ret;
EXIT_CANCEL:
    TransBuildTransOpenChannelCancelEvent(&extra, transInfo, timeStart, SOFTBUS_TRANS_STOP_BIND_BY_CANCEL);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    TransFreeAppInfo(appInfo);
    TransFreeLane(laneHandle, param->isQosLane);
    (void)TransDeleteSocketChannelInfoBySession(param->sessionName, param->sessionId);
    TRANS_LOGE(TRANS_SVC, "server open channel cancel");
    return SOFTBUS_TRANS_STOP_BIND_BY_CANCEL;
}

static AppInfo *GetAuthAppInfo(const char *mySessionName)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return NULL;
    }
    appInfo->appType = APP_TYPE_AUTH;
    appInfo->myData.apiVersion = API_V2;
    appInfo->autoCloseTime = 0;
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->channelType = CHANNEL_TYPE_AUTH;
    appInfo->timeStart = GetSoftbusRecordTimeMillis();
    appInfo->isClient = true;
    if (TransGetUidAndPid(mySessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo GetUidAndPid failed");
        goto EXIT_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo get deviceId failed");
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), mySessionName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo strcpy_s mySessionName failed");
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), mySessionName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo strcpy_s peerSessionName failed");
        goto EXIT_ERR;
    }
    if (TransGetPkgNameBySessionName(mySessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo get PkgName failed");
        goto EXIT_ERR;
    }
    if (TransCommonGetLocalConfig(appInfo->channelType, appInfo->businessType, &appInfo->myData.dataConfig) !=
        SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo get local data config failed");
        goto EXIT_ERR;
    }

    TRANS_LOGD(TRANS_CTRL, "ok");
    return appInfo;
EXIT_ERR:
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    return NULL;
}

int32_t TransOpenAuthChannel(const char *sessionName, const ConnectOption *connOpt,
    const char *reqId)
{
    int32_t channelId = INVALID_CHANNEL_ID;
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX) || connOpt == NULL) {
        return channelId;
    }
    char callerPkg[PKG_NAME_SIZE_MAX] = {0};
    char localUdid[UDID_BUF_LEN] = {0};
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    TransBuildOpenAuthChannelStartEvent(&extra, sessionName, connOpt, localUdid, callerPkg);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_START, extra);
    if (connOpt->type == CONNECT_TCP) {
        if (TransOpenAuthMsgChannel(sessionName, connOpt, &channelId, reqId) != SOFTBUS_OK) {
            goto EXIT_ERR;
        }
    } else if (connOpt->type == CONNECT_BR || connOpt->type == CONNECT_BLE) {
        AppInfo *appInfo = GetAuthAppInfo(sessionName);
        if (appInfo == NULL) {
            TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo failed");
            goto EXIT_ERR;
        }
        appInfo->connectType = connOpt->type;
        if (strcpy_s(appInfo->reqId, REQ_ID_SIZE_MAX, reqId) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "strcpy_s reqId failed");
            SoftBusFree(appInfo);
            goto EXIT_ERR;
        }
        if (TransProxyOpenProxyChannel(appInfo, connOpt, &channelId) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "proxy channel err");
            SoftBusFree(appInfo);
            goto EXIT_ERR;
        }
        SoftBusFree(appInfo);
    } else {
        goto EXIT_ERR;
    }
    return channelId;
EXIT_ERR:
    extra.result = EVENT_STAGE_RESULT_FAILED;
    extra.errcode = SOFTBUS_ERR;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    return INVALID_CHANNEL_ID;
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
        TRANS_LOGE(TRANS_STREAM, "streamStats data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneHandle;
    int32_t ret = TransGetLaneHandleByChannelId(channelId, &laneHandle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "get laneHandle fail, streamStatsInfo cannot be processed");
        return SOFTBUS_ERR;
    }
    TRANS_LOGI(TRANS_STREAM, "transStreamStats channelId=%{public}d, laneHandle=0x%{public}x", channelId, laneHandle);
    // modify with laneId
    uint64_t laneId = INVALID_LANE_ID;
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
    (void)chanType;
    (void)appType;
    uint32_t laneHandle;
    int32_t ret = TransGetLaneHandleByChannelId(channelId, &laneHandle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "get laneHandle fail, transRequestQos cannot be processed");
        return ret;
    }
    // modify with laneId
    uint64_t laneId = INVALID_LANE_ID;
    int32_t result = 0;
    if (quality == QOS_IMPROVE) {
        TRANS_LOGI(TRANS_QOS, "trans requestQos");
        ret = LnnRequestQosOptimization(&laneId, 1, &result, 1);
    } else if (quality == QOS_RECOVER) {
        TRANS_LOGI(TRANS_QOS, "trans cancel Qos");
        LnnCancelQosOptimization(&laneId, 1);
        ret = SOFTBUS_OK;
    } else {
        TRANS_LOGE(TRANS_QOS, "requestQos invalid. quality=%{public}d", quality);
        ret = SOFTBUS_ERR;
    }

    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "request Qos fail, quality=%{public}d, ret=%{public}d", quality, ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransRippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    (void)channelType;
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "rippleStats data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneHandle;
    int32_t ret = TransGetLaneHandleByChannelId(channelId, &laneHandle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get laneHandle fail, streamStatsInfo cannot be processed, ret=%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_CTRL, "transRippleStats channelId=%{public}d, laneHandle=0x%{public}x", channelId, laneHandle);
    LnnRippleData rptdata;
    (void)memset_s(&rptdata, sizeof(rptdata), 0, sizeof(rptdata));
    if (memcpy_s(&rptdata.stats, sizeof(rptdata.stats), data->stats, sizeof(data->stats)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    // modify with laneId
    uint64_t laneId = INVALID_LANE_ID;
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
            TRANS_LOGE(TRANS_CTRL, "invalid. channelId=%{public}d, channelType=%{public}d.", channelId, channelType);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL,
            "notfiy auth success. channelId=%{public}d, channelType=%{public}d, ret=%{public}d",
            channelId, channelType, ret);
        return ret;
    }
    return TransNotifyAuthDataSuccess(channelId, &connOpt);
}

int32_t TransReleaseUdpResources(int32_t channelId)
{
    TRANS_LOGI(TRANS_CTRL, "release Udp channel resources: channelId=%{public}d", channelId);
    NotifyQosChannelClosed(channelId, CHANNEL_TYPE_UDP);
    (void)TransLaneMgrDelLane(channelId, CHANNEL_TYPE_UDP);
    (void)TransDelUdpChannel(channelId);
    return SOFTBUS_OK;
}

int32_t TransCloseChannel(const char *sessionName, int32_t channelId, int32_t channelType)
{
    return TransCommonCloseChannel(sessionName, channelId, channelType);
}

int32_t TransSendMsg(int32_t channelId, int32_t channelType, const void *data, uint32_t len,
    int32_t msgType)
{
    int32_t ret = SOFTBUS_OK;
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            TRANS_LOGI(TRANS_MSG,
                "send msg auth channelType. channelId=%{public}d, channelType=%{public}d", channelId, channelType);
            ret = TransSendAuthMsg(channelId, (char*)data, (int32_t)len);
            break;
        case CHANNEL_TYPE_PROXY:
            TRANS_LOGI(TRANS_MSG,
                "send msg proxy channelType. channelId=%{public}d, channelType=%{public}d", channelId, channelType);
            ret = TransProxyPostSessionData(channelId, (unsigned char*)data, len, (SessionPktType)msgType);
            break;
        default:
            TRANS_LOGE(TRANS_MSG,
                "send msg invalid channelType. channelId=%{public}d, channelType=%{public}d", channelId, channelType);
            ret = SOFTBUS_TRANS_CHANNEL_TYPE_INVALID;
            break;
    }
    return ret;
}

void TransChannelDeathCallback(const char *pkgName, int32_t pid)
{
    TransProxyDeathCallback(pkgName, pid);
    TransTdcDeathCallback(pkgName, pid);
    TransLaneMgrDeathCallback(pkgName, pid);
    TransUdpDeathCallback(pkgName, pid);
}

int32_t TransGetNameByChanId(const TransInfo *info, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionNameLen)
{
    if (info == NULL || pkgName == NULL || sessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
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

int32_t TransGetAndComparePid(pid_t pid, int32_t channelId, int32_t channelType)
{
    if ((ChannelType)channelType == CHANNEL_TYPE_TCP_DIRECT) {
        TRANS_LOGI(TRANS_CTRL, "channel type is tcp direct!");
        return SOFTBUS_OK;
    }
    AppInfo appInfo;
    int32_t ret = TransGetAppInfoByChanId(channelId, channelType, &appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get appInfo by channelId failed, ret = %{public}d", ret);
        return ret;
    }
    pid_t curChannelPid = appInfo.myData.pid;
    if (pid != curChannelPid) {
        TRANS_LOGE(TRANS_CTRL, "callingPid not equal curChannelPid, callingPid = %{public}d, pid = %{public}d",
            pid, curChannelPid);
        return SOFTBUS_TRANS_CHECK_PID_ERROR;
    }
    TRANS_LOGI(TRANS_CTRL, "callingPid check success. callingPid=%{public}d !", curChannelPid);
    return SOFTBUS_OK;
}

int32_t TransGetAndComparePidBySession(pid_t pid, const char *sessionName, int32_t sessionlId)
{
    pid_t curSessionPid;
    int32_t ret = TransGetPidFromSocketChannelInfoBySession(sessionName, sessionlId, &curSessionPid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get pid by session failed, ret = %{public}d", ret);
        return ret;
    }
    if (pid != curSessionPid) {
        TRANS_LOGE(TRANS_CTRL, "callingPid not equal curSessionPid, callingPid=%{public}d, pid=%{public}d",
            pid, curSessionPid);
        return SOFTBUS_TRANS_CHECK_PID_ERROR;
    }
    TRANS_LOGI(TRANS_CTRL, "callingPid check success. callingPid=%{public}d !", pid);
    return SOFTBUS_OK;
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
    int32_t ret;

    switch (channelType) {
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyGetConnIdByChanId(channelId, connId);
            break;
        case CHANNEL_TYPE_AUTH:
            ret = TransAuthGetConnIdByChanId(channelId, connId);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "channelType=%{public}d error", channelType);
            ret = SOFTBUS_ERR;
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_MSG, "get connId failed, channelId=%{public}d, channelType=%{public}d",
            channelId, channelType);
    }

    return ret;
}
