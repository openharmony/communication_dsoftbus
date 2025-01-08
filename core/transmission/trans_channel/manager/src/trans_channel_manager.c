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
#include "legacy/softbus_hisysevt_transreporter.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_qos.h"
#include "message_handler.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_qos.h"
#include "softbus_utils.h"
#include "trans_auth_lane_pending_ctl.h"
#include "trans_auth_manager.h"
#include "trans_auth_negotiation.h"
#include "trans_bind_request_manager.h"
#include "trans_channel_callback.h"
#include "trans_channel_common.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_lane_pending_ctl.h"
#include "trans_link_listener.h"
#include "trans_log.h"
#include "trans_network_statistics.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"

#define MAX_PROXY_CHANNEL_ID 0x00000800
#define MAX_TDC_CHANNEL_ID 0x7FFFFFFF
#define MIN_FD_ID 1025
#define MAX_FD_ID 2048
#define MAX_PROXY_CHANNEL_ID_COUNT 1024
#define ID_NOT_USED 0
#define ID_USED 1UL
#define BIT_NUM 8
#define REPORT_UDP_INFO_SIZE 4

static int32_t g_allocTdcChannelId = MAX_PROXY_CHANNEL_ID;
static SoftBusMutex g_myIdLock;
static unsigned long g_proxyChanIdBits[MAX_PROXY_CHANNEL_ID_COUNT / BIT_NUM / sizeof(long)] = {0};
static uint32_t g_proxyIdMark = 0;
static uint32_t g_channelIdCount = 0;

const char *g_channelResultLoopName = "transChannelResultLoopName";
SoftBusHandler g_channelResultHandler = { 0 };

typedef enum {
    LOOP_CHANNEL_OPEN_MSG,
    LOOP_LIMIT_CHANGE_MSG,
} ChannelResultLoopMsg;

typedef struct {
    ListNode node;
    int32_t pid;
    char pkgName[PKG_NAME_SIZE_MAX];
} PrivilegeCloseChannelInfo;

static int32_t GenerateTdcChannelId()
{
    int32_t channelId;
    if (SoftBusMutexLock(&g_myIdLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
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
    if (SoftBusMutexLock(&g_myIdLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
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
    if (SoftBusMutexLock(&g_myIdLock) != SOFTBUS_OK) {
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

void TransAsyncChannelOpenTaskManager(int32_t channelId, int32_t channelType)
{
    switch (channelType) {
        case CHANNEL_TYPE_PROXY:
            TransAsyncProxyChannelTask(channelId);
            break;
        case CHANNEL_TYPE_TCP_DIRECT:
            TransAsyncTcpDirectChannelTask(channelId);
            break;
        case CHANNEL_TYPE_UDP:
            TransAsyncUdpChannelTask(channelId);
            break;
        case CHANNEL_TYPE_AUTH:
            TransAsyncAuthChannelTask(channelId);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "channelType=%{public}d is error!", channelType);
    }
}

static void TransChannelResultLoopMsgHandler(SoftBusMessage *msg)
{
    TRANS_CHECK_AND_RETURN_LOGE(msg != NULL, TRANS_MSG, "param msg is invalid");
    int32_t channelId;
    int32_t channelType;
    if (msg->what == LOOP_CHANNEL_OPEN_MSG) {
        channelId = (int32_t)msg->arg1;
        channelType = (int32_t)msg->arg2;
        TransAsyncChannelOpenTaskManager(channelId, channelType);
    }
}

int32_t TransChannelResultLoopInit(void)
{
    g_channelResultHandler.name = (char *)g_channelResultLoopName;
    g_channelResultHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_channelResultHandler.looper == NULL) {
        return SOFTBUS_TRANS_INIT_FAILED;
    }
    g_channelResultHandler.HandleMessage = TransChannelResultLoopMsgHandler;
    return SOFTBUS_OK;
}

static void TransChannelResultFreeLoopMsg(SoftBusMessage *msg)
{
    if (msg != NULL) {
        if (msg->obj != NULL) {
            SoftBusFree(msg->obj);
        }
        SoftBusFree((void *)msg);
    }
}

static SoftBusMessage *TransChannelResultCreateLoopMsg(int32_t what, uint64_t arg1, uint64_t arg2, char *data)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TRANS_LOGE(TRANS_MSG, "msg calloc failed");
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_channelResultHandler;
    msg->FreeMessage = TransChannelResultFreeLoopMsg;
    msg->obj = (void *)data;
    return msg;
}

void TransCheckChannelOpenToLooperDelay(int32_t channelId, int32_t channelType, uint32_t delayTime)
{
    SoftBusMessage *msg  = TransChannelResultCreateLoopMsg(LOOP_CHANNEL_OPEN_MSG, channelId, channelType, NULL);
    TRANS_CHECK_AND_RETURN_LOGE(msg != NULL, TRANS_MSG, "msg create failed");

    g_channelResultHandler.looper->PostMessageDelay(g_channelResultHandler.looper, msg, delayTime);
}

static int32_t RemoveMessageDestroy(const SoftBusMessage *msg, void *data)
{
    int32_t channelId = *(int32_t *)data;
    if (msg->what == LOOP_CHANNEL_OPEN_MSG && channelId == (int32_t)msg->arg1) {
        TRANS_LOGE(TRANS_CTRL, "remove delay check channel opened message succ, channelId=%{public}d.", channelId);
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

void TransCheckChannelOpenRemoveFromLooper(int32_t channelId)
{
    g_channelResultHandler.looper->RemoveMessageCustom(
        g_channelResultHandler.looper, &g_channelResultHandler, RemoveMessageDestroy, &channelId);
}

int32_t TransChannelInit(void)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    TRANS_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_NO_INIT, TRANS_INIT, "cd is null.");

    int32_t ret = TransLaneMgrInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans lane manager init failed.");

    ret = TransSocketLaneMgrInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans socket lane manager init failed.");

    ret = TransAuthInit(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans auth init failed.");

    ret = TransProxyManagerInit(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans proxy manager init failed.");

    ret = TransTcpDirectInit(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans tcp direct init failed.");

    ret = TransUdpChannelInit(cb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans udp channel init failed.");

    ret = TransBindRequestManagerInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans bind request manager init failed.");

    ret = TransReqLanePendingInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans req lane pending init failed.");

    ret = TransNetworkStatisticsInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans network statistics init failed.");

    ret = TransAsyncReqLanePendingInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans async req lane pending init failed.");

    ret = TransReqAuthPendingInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans auth request pending init failed.");
    ret = TransAuthWithParaReqLanePendingInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_INIT, "trans auth with para req lane pending init failed.");

    ret = TransFreeLanePendingInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans free lane pending init failed.");

    ret = TransChannelResultLoopInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "trans channel result loop init failed.");

    ReqLinkListener();
    ret = SoftBusMutexInit(&g_myIdLock, NULL);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "init lock failed.");
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
    TransNetworkStatisticsDeinit();
    TransReqAuthPendingDeinit();
    TransAuthWithParaReqLanePendingDeinit();
    TransFreeLanePendingDeinit();
    TransBindRequestManagerDeinit();
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

static void TransSetQosInfo(const QosTV *qos, uint32_t qosCount, TransEventExtra *extra)
{
    if (qosCount > QOS_TYPE_BUTT) {
        TRANS_LOGE(TRANS_CTRL, "qos count error, qosCount=%{public}" PRIu32, qosCount);
        return;
    }

    for (uint32_t i = 0; i < qosCount; i++) {
        switch (qos[i].qos) {
            case QOS_TYPE_MIN_BW:
                extra->minBW = qos[i].value;
                break;
            case QOS_TYPE_MAX_LATENCY:
                extra->maxLatency = qos[i].value;
                break;
            case QOS_TYPE_MIN_LATENCY:
                extra->minLatency = qos[i].value;
                break;
            default:
                break;
        }
    }
}

static bool IsLaneModuleError(int32_t errcode)
{
    if (errcode >= SOFTBUS_LANE_ERR_BASE && errcode < SOFTBUS_CONN_ERR_BASE) {
        return true;
    }
    return false;
}

static void TransFreeLaneInner(uint32_t laneHandle, bool isQosLane, bool isAsync)
{
    if (isQosLane) {
        TransFreeLaneByLaneHandle(laneHandle, isAsync);
    } else {
        LnnFreeLane(laneHandle);
    }
}

int32_t TransOpenChannel(const SessionParam *param, TransInfo *transInfo)
{
    if (param == NULL || transInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetDeniedFlagByPeer(param->sessionName, param->peerSessionName, param->peerDeviceId)) {
        TRANS_LOGE(TRANS_CTRL, "request denied: sessionId=%{public}d", param->sessionId);
        return SOFTBUS_TRANS_BIND_REQUEST_DENIED;
    }
    char *tmpName = NULL;
    Anonymize(param->sessionName, &tmpName);
    TRANS_LOGI(TRANS_CTRL, "server TransOpenChannel, sessionName=%{public}s, socket=%{public}d, actionId=%{public}d, "
                           "isQosLane=%{public}d, isAsync=%{public}d",
        AnonymizeWrapper(tmpName), param->sessionId, param->actionId, param->isQosLane, param->isAsync);
    AnonymizeFree(tmpName);
    int32_t ret = INVALID_CHANNEL_ID;
    uint32_t laneHandle = INVALID_LANE_REQ_ID;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    TRANS_CHECK_AND_RETURN_RET_LOGE(appInfo != NULL, SOFTBUS_MALLOC_ERR, TRANS_CTRL, "calloc appInfo failed.");
    ret = TransCommonGetAppInfo(param, appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get appinfo failed");
        TransFreeAppInfo(appInfo);
        return ret;
    }
    ret = TransAddSocketChannelInfo(
        param->sessionName, param->sessionId, INVALID_CHANNEL_ID, CHANNEL_TYPE_UNDEFINED, CORE_SESSION_STATE_INIT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Add socket channel record failed.");
        TransFreeAppInfo(appInfo);
        return ret;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t peerRet = LnnGetRemoteNodeInfoById(appInfo->peerNetWorkId, CATEGORY_NETWORK_ID, &nodeInfo);
    appInfo->osType = nodeInfo.deviceInfo.osType;
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    TransBuildTransOpenChannelStartEvent(&extra, appInfo, &nodeInfo, peerRet);
    TransSetFirstTokenInfo(appInfo, &extra);
    TransSetQosInfo(param->qos, param->qosCount, &extra);
    extra.sessionId = param->sessionId;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_START, extra);
    if (param->isQosLane) {
        uint32_t callingTokenId = TransACLGetCallingTokenID();
        ret = TransAsyncGetLaneInfo(param, &laneHandle, callingTokenId, appInfo->timeStart);
        if (ret != SOFTBUS_OK) {
            Anonymize(param->sessionName, &tmpName);
            TRANS_LOGE(TRANS_CTRL, "Async get Lane failed, sessionName=%{public}s, sessionId=%{public}d",
                AnonymizeWrapper(tmpName), param->sessionId);
            AnonymizeFree(tmpName);
            if (ret != SOFTBUS_TRANS_STOP_BIND_BY_CANCEL) {
                TransFreeLaneInner(laneHandle, param->isQosLane, param->isAsync);
            }
            (void)TransDeleteSocketChannelInfoBySession(param->sessionName, param->sessionId);
        }
        TransFreeAppInfo(appInfo);
        return ret;
    }
    transInfo->channelId = INVALID_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_BUTT;
    LaneConnInfo connInfo;
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    if (ret != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_GET_LANE_INFO_ERR);
        goto EXIT_ERR;
    }
    Anonymize(param->sessionName, &tmpName);
    TRANS_LOGI(TRANS_CTRL,
        "sessionName=%{public}s, socket=%{public}d, laneHandle=%{public}u, linkType=%{public}u.",
        AnonymizeWrapper(tmpName), param->sessionId, laneHandle, connInfo.type);
    AnonymizeFree(tmpName);
    ret = TransGetConnectOptByConnInfo(&connInfo, &connOpt);
    if (ret != SOFTBUS_OK) {
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, connInfo.type,
            SOFTBUS_EVT_OPEN_SESSION_FAIL, GetSoftbusRecordTimeMillis() - appInfo->timeStart);
        goto EXIT_ERR;
    }
    appInfo->connectType = connOpt.type;
    extra.linkType = connOpt.type;
    extra.deviceState = TransGetDeviceState(param->peerDeviceId);
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
    (void)memset_s(appInfo->sessionKey, sizeof(appInfo->sessionKey), 0, sizeof(appInfo->sessionKey));
    if (ret != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_CREATE_CHANNEL_ERR);
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName,
            appInfo->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, GetSoftbusRecordTimeMillis() - appInfo->timeStart);
        goto EXIT_ERR;
    }
    if (TransUpdateSocketChannelInfoBySession(
        param->sessionName, param->sessionId, transInfo->channelId, transInfo->channelType) != SOFTBUS_OK) {
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, appInfo->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL,
            GetSoftbusRecordTimeMillis() - appInfo->timeStart);
        TransCloseChannel(NULL, transInfo->channelId, transInfo->channelType);
        goto EXIT_ERR;
    }
    TransSetSocketChannelStateByChannel(
        transInfo->channelId, transInfo->channelType, CORE_SESSION_STATE_CHANNEL_OPENED);
    if (TransLaneMgrAddLane(transInfo, &connInfo, laneHandle, param->isQosLane, &appInfo->myData) != SOFTBUS_OK) {
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, appInfo->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL,
            GetSoftbusRecordTimeMillis() - appInfo->timeStart);
        TransCloseChannel(NULL, transInfo->channelId, transInfo->channelType);
        goto EXIT_ERR;
    }
    AddChannelStatisticsInfo(transInfo->channelId, transInfo->channelType);
    TransFreeAppInfo(appInfo);
    TRANS_LOGI(TRANS_CTRL,
        "server TransOpenChannel ok: socket=%{public}d, channelId=%{public}d, channelType=%{public}d, "
        "laneHandle=%{public}u",
        param->sessionId, transInfo->channelId, transInfo->channelType, laneHandle);
    return SOFTBUS_OK;
EXIT_ERR:
    extra.linkType = IsLaneModuleError(ret) ? extra.linkType : CONNECT_HML;
    TransBuildTransOpenChannelEndEvent(&extra, transInfo, appInfo->timeStart, ret);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    TransAlarmExtra extraAlarm;
    TransBuildTransAlarmEvent(&extraAlarm, appInfo, ret);
    TRANS_ALARM(OPEN_SESSION_FAIL_ALARM, CONTROL_ALARM_TYPE, extraAlarm);
    TransFreeAppInfo(appInfo);
    if (ret != SOFTBUS_TRANS_STOP_BIND_BY_CANCEL || laneHandle != INVALID_LANE_REQ_ID) {
        TransFreeLaneInner(laneHandle, param->isQosLane, param->isAsync);
    }
    (void)TransDeleteSocketChannelInfoBySession(param->sessionName, param->sessionId);
    TRANS_LOGE(TRANS_SVC, "server TransOpenChannel err, socket=%{public}d, ret=%{public}d", param->sessionId, ret);
    return ret;
EXIT_CANCEL:
    TransBuildTransOpenChannelCancelEvent(&extra, transInfo, appInfo->timeStart, SOFTBUS_TRANS_STOP_BIND_BY_CANCEL);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    TransFreeAppInfo(appInfo);
    TransFreeLaneInner(laneHandle, param->isQosLane, param->isAsync);
    (void)TransDeleteSocketChannelInfoBySession(param->sessionName, param->sessionId);
    TRANS_LOGE(TRANS_SVC, "server open channel cancel, socket=%{public}d", param->sessionId);
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
    SoftBusFree(appInfo);
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
    extra.errcode = SOFTBUS_TRANS_AUTH_CHANNEL_NOT_FOUND;
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
        return ret;
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
        ret = SOFTBUS_TRANS_REQUEST_QOS_INVALID;
    }

    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "request Qos fail, quality=%{public}d, ret=%{public}d", quality, ret);
        return SOFTBUS_TRANS_REQUEST_QOS_FAILED;
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
    int32_t ret = SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    ConnectOption connOpt;
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            ret = TransAuthGetConnOptionByChanId(channelId, &connOpt);
            break;
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyGetConnOptionByChanId(channelId, &connOpt);
            break;
        default:
            ret = SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
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
    (void)TransLaneMgrDelLane(channelId, CHANNEL_TYPE_UDP, false);
    (void)TransDelUdpChannel(channelId);
    return SOFTBUS_OK;
}

int32_t TransCloseChannel(const char *sessionName, int32_t channelId, int32_t channelType)
{
    int32_t ret = TransCommonCloseChannel(sessionName, channelId, channelType);
    if (IsTdcRecoveryTransLimit() && IsUdpRecoveryTransLimit()) {
        UdpChannelFileTransRecoveryLimit(FILE_PRIORITY_BE);
    }
    return ret;
}

int32_t TransCloseChannelWithStatistics(int32_t channelId, int32_t channelType, uint64_t laneId,
    const void *dataInfo, uint32_t len)
{
    UpdateNetworkResourceByLaneId(channelId, channelType, laneId, dataInfo, len);
    return SOFTBUS_OK;
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
            TRANS_LOGD(TRANS_MSG,
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
    TransTdcChannelInfoDeathCallback(pkgName, pid);
    TransLaneMgrDeathCallback(pkgName, pid);
    TransUdpDeathCallback(pkgName, pid);
    TransAuthDeathCallback(pkgName, pid);
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
    int32_t curChannelPid;
    int32_t ret = SOFTBUS_OK;
    if ((ChannelType)channelType == CHANNEL_TYPE_TCP_DIRECT) {
        ret = TransGetPidByChanId(channelId, channelType, &curChannelPid);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get pid by channelId failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
            return ret;
        }
    } else {
        AppInfo appInfo;
        ret = TransGetAppInfoByChanId(channelId, channelType, &appInfo);
        (void)memset_s(appInfo.sessionKey, sizeof(appInfo.sessionKey), 0, sizeof(appInfo.sessionKey));
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get appInfo by channelId failed, channelId=%{public}d, ret=%{public}d",
                channelId, ret);
            return ret;
        }
        curChannelPid = appInfo.myData.pid;
    }
    if (pid != (pid_t)curChannelPid) {
        TRANS_LOGE(TRANS_CTRL, "callingPid=%{public}d not equal curChannelPid=%{public}d", pid, curChannelPid);
        return SOFTBUS_TRANS_CHECK_PID_ERROR;
    }
    return SOFTBUS_OK;
}

int32_t TransGetAndComparePidBySession(pid_t pid, const char *sessionName, int32_t sessionlId)
{
    pid_t curSessionPid;
    int32_t ret = TransGetPidFromSocketChannelInfoBySession(sessionName, sessionlId, &curSessionPid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get pid by session failed, ret=%{public}d", ret);
        return ret;
    }
    if (pid != curSessionPid) {
        TRANS_LOGE(TRANS_CTRL, "callingPid=%{public}d not equal curSessionPid=%{public}d", pid, curSessionPid);
        return SOFTBUS_TRANS_CHECK_PID_ERROR;
    }
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
            ret = SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_MSG, "get connId failed, channelId=%{public}d, channelType=%{public}d",
            channelId, channelType);
    }

    return ret;
}

int32_t CheckAuthChannelIsExit(ConnectOption *connInfo)
{
    if (connInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    
    int32_t ret = SOFTBUS_TRANS_NOT_MATCH;
    if (connInfo->type == CONNECT_TCP) {
        ret = CheckIsWifiAuthChannel(connInfo);
    } else if (connInfo->type == CONNECT_BR || connInfo->type == CONNECT_BLE) {
        ret = CheckIsProxyAuthChannel(connInfo);
    }
    TRANS_LOGW(TRANS_CTRL, "connInfo type=%{public}d, ret=%{public}d", connInfo->type, ret);
    return ret;
}

static int32_t GetChannelInfoFromBuf(
    uint8_t *buf, int32_t *channelId, int32_t *channelType, int32_t *openResult, uint32_t len)
{
    int32_t offSet = 0;
    int32_t ret = SOFTBUS_OK;
    ret = ReadInt32FromBuf(buf, len, &offSet, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channelId from buf failed!");
        return ret;
    }
    ret = ReadInt32FromBuf(buf, len, &offSet, channelType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channelId from buf failed!");
        return ret;
    }
    ret = ReadInt32FromBuf(buf, len, &offSet, openResult);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get openResult from buf failed!");
        return ret;
    }
    return ret;
}

static int32_t GetUdpChannelInfoFromBuf(
    uint8_t *buf, int32_t *channelId, int32_t *channelType, int32_t *openResult, int32_t *udpPort, uint32_t len)
{
    int32_t offSet = 0;
    int32_t ret = SOFTBUS_OK;
    ret = ReadInt32FromBuf(buf, len, &offSet, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channelId from buf failed!");
        return ret;
    }
    ret = ReadInt32FromBuf(buf, len, &offSet, channelType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channelId from buf failed!");
        return ret;
    }
    ret = ReadInt32FromBuf(buf, len, &offSet, openResult);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get openResult from buf failed!");
        return ret;
    }
    ret = ReadInt32FromBuf(buf, len, &offSet, udpPort);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get udpPort from buf failed!");
        return ret;
    }
    return ret;
}

static int32_t GetLimitChangeInfoFromBuf(
    uint8_t *buf, int32_t *channelId, uint8_t *tos, int32_t *limitChangeResult, uint32_t len)
{
    int32_t offSet = 0;
    int32_t ret = SOFTBUS_OK;
    ret = ReadInt32FromBuf(buf, len, &offSet, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channelId from buf failed!");
        return ret;
    }
    ret = ReadUint8FromBuf(buf, len, &offSet, tos);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get tos from buf failed!");
        return ret;
    }
    ret = ReadInt32FromBuf(buf, len, &offSet, limitChangeResult);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get limitChangeResult from buf failed!");
        return ret;
    }
    return ret;
}

static int32_t TransReportChannelOpenedInfo(uint8_t *buf, uint32_t len)
{
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t openResult = 0;
    int32_t udpPort = 0;
    int32_t ret = SOFTBUS_OK;
    if (len == sizeof(int32_t) * REPORT_UDP_INFO_SIZE) {
        ret = GetUdpChannelInfoFromBuf(buf, &channelId, &channelType, &openResult, &udpPort, len);
    } else {
        ret = GetChannelInfoFromBuf(buf, &channelId, &channelType, &openResult, len);
    }
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    switch (channelType) {
        case CHANNEL_TYPE_PROXY:
            ret = TransDealProxyChannelOpenResult(channelId, openResult);
            break;
        case CHANNEL_TYPE_TCP_DIRECT:
            ret = TransDealTdcChannelOpenResult(channelId, openResult);
            break;
        case CHANNEL_TYPE_UDP:
            ret = TransDealUdpChannelOpenResult(channelId, openResult, udpPort);
            break;
        case CHANNEL_TYPE_AUTH:
            ret = TransDealAuthChannelOpenResult(channelId, openResult);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "channelType=%{public}d is error", channelType);
            ret = SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "report Event channel opened info failed");
    }
    return ret;
}

static void TransReportLimitChangeInfo(uint8_t *buf, uint32_t len)
{
    int32_t channelId = 0;
    uint8_t tos = 0;
    int32_t limitChangeResult = 0;
    int32_t ret = SOFTBUS_OK;
    ret = GetLimitChangeInfoFromBuf(buf, &channelId, &tos, &limitChangeResult, len);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetLimitChangeInfoFromBuf failed, ret=%{public}d", ret);
    }
    if (limitChangeResult != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "limitChangeResult is failed, limitChangeResult=%{public}d", limitChangeResult);
    }
    ret = TransSetTos(channelId, tos);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Set limit change event failed, ret=%{public}d", ret);
    }
}

static int32_t GetCollabCheckResultFromBuf(uint8_t *buf,
    int32_t *channelId, int32_t *channelType, int32_t *checkResult, uint32_t len)
{
    int32_t offset = 0;
    int32_t ret = ReadInt32FromBuf(buf, len, &offset, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channelId from buf failed.");
        return ret;
    }
    ret = ReadInt32FromBuf(buf, len, &offset, channelType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channelType from buf failed.");
        return ret;
    }
    ret = ReadInt32FromBuf(buf, len, &offset, checkResult);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get checkResult from buf failed.");
        return ret;
    }
    return ret;
}

static int32_t TransReportCheckCollabInfo(uint8_t *buf, uint32_t len)
{
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t checkResult = 0;
    int32_t ret = GetCollabCheckResultFromBuf(buf, &channelId, &channelType, &checkResult, len);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    switch (channelType) {
        case CHANNEL_TYPE_PROXY:
            ret = TransDealProxyCheckCollabResult(channelId, checkResult);
            break;
        case CHANNEL_TYPE_TCP_DIRECT:
            ret = TransDealTdcCheckCollabResult(channelId, checkResult);
            break;
        case CHANNEL_TYPE_UDP:
            ret = TransDealUdpCheckCollabResult(channelId, checkResult);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "channelType=%{public}d is error.", channelType);
            ret = SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    return ret;
}

int32_t TransProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len)
{
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "process inner event buf is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    switch (eventType) {
        case EVENT_TYPE_CHANNEL_OPENED:
            ret = TransReportChannelOpenedInfo(buf, len);
            break;
        case EVENT_TYPE_TRANS_LIMIT_CHANGE:
            TransReportLimitChangeInfo(buf, len);
            break;
        case EVENT_TYPE_COLLAB_CHECK:
            ret = TransReportCheckCollabInfo(buf, len);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "eventType=%{public}d error", eventType);
            ret = SOFTBUS_TRANS_MSG_INVALID_EVENT_TYPE;
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "report event failed, eventType=%{public}d", eventType);
    }
    return ret;
}

int32_t TransPrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId)
{
#define PRIVILEGE_CLOSE_OFFSET 11
    if (peerNetworkId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ListNode privilegeCloseList;
    ListInit(&privilegeCloseList);
    (void)TransTcpGetPrivilegeCloseList(&privilegeCloseList, tokenId, pid);
    (void)TransProxyGetPrivilegeCloseList(&privilegeCloseList, tokenId, pid);
    (void)TransUdpGetPrivilegeCloseList(&privilegeCloseList, tokenId, pid);
    LinkDownInfo info = {
        .uuid = "",
        .udid = "",
        .peerIp = "",
        .networkId = peerNetworkId,
        .routeType = ROUTE_TYPE_ALL | 1 << PRIVILEGE_CLOSE_OFFSET,
    };
    PrivilegeCloseChannelInfo *pos = NULL;
    PrivilegeCloseChannelInfo *tmp = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &privilegeCloseList, PrivilegeCloseChannelInfo, node) {
        (void)TransServerOnChannelLinkDown(pos->pkgName, pos->pid, &info);
        ListDelete(&(pos->node));
        SoftBusFree(pos);
    }
    return SOFTBUS_OK;
}

int32_t PrivilegeCloseListAddItem(ListNode *privilegeCloseList, int32_t pid, const char *pkgName)
{
    if (privilegeCloseList == NULL || pkgName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    PrivilegeCloseChannelInfo *exitItem = NULL;
    LIST_FOR_EACH_ENTRY(exitItem, privilegeCloseList, PrivilegeCloseChannelInfo, node) {
        if (strcmp(exitItem->pkgName, pkgName) == 0 && exitItem->pid == pid) {
            return SOFTBUS_OK;
        }
    }
    PrivilegeCloseChannelInfo *item = (PrivilegeCloseChannelInfo *)SoftBusCalloc(sizeof(PrivilegeCloseChannelInfo));
    TRANS_CHECK_AND_RETURN_RET_LOGE(item != NULL, SOFTBUS_MALLOC_ERR, TRANS_CTRL, "calloc failed");
    if (strcpy_s(item->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_STRCPY_ERR;
    }
    item->pid = pid;
    ListInit(&(item->node));
    ListAdd(privilegeCloseList, &(item->node));
    TRANS_LOGI(TRANS_CTRL, "add success, pkgName=%{public}s, pid=%{public}d", pkgName, pid);
    return SOFTBUS_OK;
}