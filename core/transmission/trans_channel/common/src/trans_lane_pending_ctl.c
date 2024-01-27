/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "trans_lane_pending_ctl.h"

#include <securec.h>
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "trans_event.h"

#define TRANS_REQUEST_PENDING_TIMEOUT (5000)
#define SESSION_NAME_PHONEPAD "com.huawei.pcassistant.phonepad-connect-channel"
#define SESSION_NAME_CASTPLUS "CastPlusSessionName"
#define SESSION_NAME_DISTRIBUTE_COMMUNICATION "com.huawei.boosterd.user"
#define SESSION_NAME_ISHARE "IShare"
#define ISHARE_MIN_NAME_LEN 6

typedef struct {
    ListNode node;
    uint32_t laneId;
    int32_t errCode;
    SoftBusCond cond;
    bool bSucc;
    bool isFinished;
    LaneConnInfo connInfo;
} TransReqLaneItem;

static SoftBusList *g_reqLanePendingList = NULL;

int32_t TransReqLanePendingInit(void)
{
    g_reqLanePendingList = CreateSoftBusList();
    if (g_reqLanePendingList == NULL) {
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

void TransReqLanePendingDeinit(void)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if (g_reqLanePendingList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_reqLanePendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "lock failed.");
        return;
    }

    TransReqLaneItem *item = NULL;
    TransReqLaneItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_reqLanePendingList->list, TransReqLaneItem, node) {
        (void)SoftBusCondDestroy(&item->cond);
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_reqLanePendingList->lock);
    DestroySoftBusList(g_reqLanePendingList);
    g_reqLanePendingList = NULL;
}

static int32_t TransDelLaneReqFromPendingList(uint32_t laneId)
{
    TRANS_LOGD(TRANS_SVC, "del tran request from pending laneId=%{public}u", laneId);
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "lane request list hasn't init.");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *laneItem = NULL;
    TransReqLaneItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (laneItem->laneId == laneId) {
            (void)SoftBusCondDestroy(&laneItem->cond);
            ListDelete(&(laneItem->node));
            TRANS_LOGI(TRANS_SVC, "delete laneId = %{public}u", laneItem->laneId);
            g_reqLanePendingList->cnt--;
            SoftBusFree(laneItem);
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane request not found, laneId=%{public}u", laneId);
    return SOFTBUS_ERR;
}

static int32_t TransAddLaneReqFromPendingList(uint32_t laneId)
{
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "lane pending list no init.");
        return SOFTBUS_ERR;
    }

    TransReqLaneItem *item = (TransReqLaneItem *)SoftBusCalloc(sizeof(TransReqLaneItem));
    if (item == NULL) {
        TRANS_LOGE(TRANS_SVC, "malloc lane request item err.");
        return SOFTBUS_MALLOC_ERR;
    }
    item->errCode = SOFTBUS_ERR;
    item->laneId = laneId;
    item->bSucc = false;
    item->isFinished = false;

    if (SoftBusMutexLock(&g_reqLanePendingList->lock) != SOFTBUS_OK) {
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (SoftBusCondInit(&item->cond) != 0) {
        SoftBusFree(item);
        (void)SoftBusMutexUnlock(&g_reqLanePendingList->lock);
        TRANS_LOGE(TRANS_SVC, "cond init failed.");
        return SOFTBUS_ERR;
    }
    ListInit(&(item->node));
    ListAdd(&(g_reqLanePendingList->list), &(item->node));
    g_reqLanePendingList->cnt++;
    (void)SoftBusMutexUnlock(&g_reqLanePendingList->lock);

    TRANS_LOGI(TRANS_SVC, "add tran request to pending laneId=%{public}u", laneId);
    return SOFTBUS_OK;
}

static int32_t TransGetLaneReqItemByLaneId(uint32_t laneId, bool *bSucc, LaneConnInfo *connInfo, int32_t *errCode)
{
    if (bSucc == NULL || connInfo == NULL) {
        TRANS_LOGE(TRANS_SVC, "param err.");
        return SOFTBUS_ERR;
    }
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane request list hasn't init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (item->laneId == laneId) {
            *bSucc = item->bSucc;
            *errCode = item->errCode;
            if (memcpy_s(connInfo, sizeof(LaneConnInfo), &(item->connInfo), sizeof(LaneConnInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneId=%{public}u", laneId);
    return SOFTBUS_ERR;
}

static int32_t TransUpdateLaneConnInfoByLaneId(uint32_t laneId, bool bSucc,
    const LaneConnInfo *connInfo, int32_t errCode)
{
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane request list hasn't init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (item->laneId == laneId) {
            item->bSucc = bSucc;
            item->errCode = errCode;
            if ((connInfo != NULL) &&
                (memcpy_s(&(item->connInfo), sizeof(LaneConnInfo), connInfo, sizeof(LaneConnInfo)) != EOK)) {
                (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
                return SOFTBUS_ERR;
            }
            item->isFinished = true;
            (void)SoftBusCondSignal(&item->cond);
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneId=%{public}u", laneId);
    return SOFTBUS_ERR;
}

static void TransOnLaneRequestSuccess(uint32_t laneId, const LaneConnInfo *connInfo)
{
    TRANS_LOGI(TRANS_SVC, "request success. laneId=%{public}u", laneId);
    if (TransUpdateLaneConnInfoByLaneId(laneId, true, connInfo, SOFTBUS_OK) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "update lane connInfo failed, laneId=%{public}u", laneId);
    }
    return;
}

static void TransOnLaneRequestFail(uint32_t laneId, int32_t reason)
{
    TRANS_LOGI(TRANS_SVC, "request failed, laneId=%{public}u, reason=%{public}d", laneId, reason);
    if (TransUpdateLaneConnInfoByLaneId(laneId, false, NULL, reason) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "update lane connInfo failed, laneId=%{public}u", laneId);
    }
    return;
}

static void TransOnLaneStateChange(uint32_t laneId, LaneState state)
{
    /* current no treatment */
    (void)laneId;
    (void)state;
    return;
}

static LaneTransType GetStreamLaneType(int32_t streamType)
{
    switch (streamType) {
        case RAW_STREAM:
            return LANE_T_RAW_STREAM;
        case COMMON_VIDEO_STREAM:
            return LANE_T_COMMON_VIDEO;
        case COMMON_AUDIO_STREAM:
            return LANE_T_COMMON_VOICE;
        default:
            break;
    }
    return LANE_T_BUTT;
}

LaneTransType TransGetLaneTransTypeBySession(const SessionParam *param)
{
    if (param == NULL || param->attr == NULL) {
        return LANE_T_BUTT;
    }
    int32_t type = param->attr->dataType;
    int32_t streamType;
    switch (type) {
        case TYPE_MESSAGE:
            return LANE_T_MSG;
        case TYPE_BYTES:
            return LANE_T_BYTE;
        case TYPE_FILE:
            return LANE_T_FILE;
        case TYPE_STREAM:
            streamType = param->attr->attr.streamAttr.streamType;
            return GetStreamLaneType(streamType);
        default:
            break;
    }

    TRANS_LOGE(TRANS_SVC, "session type no support. type=%{public}u", type);
    return LANE_T_BUTT;
}

static const LaneLinkType g_laneMap[LINK_TYPE_MAX + 1] = {
    LANE_LINK_TYPE_BUTT,
    LANE_WLAN_5G,
    LANE_WLAN_2P4G,
    LANE_P2P,
    LANE_BR,
    LANE_BLE,
    LANE_P2P_REUSE,
    LANE_BLE_DIRECT,
    LANE_COC,
    LANE_COC_DIRECT,
};
static LaneLinkType TransGetLaneLinkTypeBySessionLinkType(LinkType type)
{
    return g_laneMap[type];
}

static void TransformSessionPreferredToLanePreferred(const SessionParam *param,
    LanePreferredLinkList *preferred, TransOption *transOption)
{
    (void)transOption;
    if (param->attr->linkTypeNum <= 0 || param->attr->linkTypeNum > LINK_TYPE_MAX) {
        preferred->linkTypeNum = 0;
        return;
    }
    preferred->linkTypeNum = 0;
    for (int32_t i = 0; i < param->attr->linkTypeNum; ++i) {
        LaneLinkType linkType = TransGetLaneLinkTypeBySessionLinkType(param->attr->linkType[i]);
        if (linkType == LANE_LINK_TYPE_BUTT) {
            continue;
        }
        if (preferred->linkTypeNum >= LINK_TYPE_MAX) {
            TRANS_LOGE(TRANS_SVC,
                "session preferred linknum override lane maxcnt=%{public}d.", LANE_LINK_TYPE_BUTT);
            break;
        }
        preferred->linkType[preferred->linkTypeNum] = linkType;
        preferred->linkTypeNum += 1;
    }
    return;
}

static bool IsShareSession(const char *sessionName)
{
    if (strlen(sessionName) < ISHARE_MIN_NAME_LEN ||
        strncmp(sessionName, SESSION_NAME_ISHARE, ISHARE_MIN_NAME_LEN) != 0) {
        return false;
    }
    return true;
}

static void TransGetQosInfo(const SessionParam *param, QosInfo *qosInfo, bool *isQosLane)
{
    *isQosLane = param->isQosLane;
    if (!(*isQosLane)) {
        TRANS_LOGD(TRANS_SVC, "not support qos lane");
        return;
    }

    for (uint32_t i = 0; i < param->qosCount; i++) {
        switch (param->qos[i].qos) {
            case QOS_TYPE_MIN_BW:
                qosInfo->minBW = param->qos[i].value;
                break;
            case QOS_TYPE_MAX_LATENCY:
                qosInfo->maxLaneLatency = param->qos[i].value;
                break;
            case QOS_TYPE_MIN_LATENCY:
                qosInfo->minLaneLatency = param->qos[i].value;
                break;
            default:
                break;
        }
    }
}

#ifdef SOFTBUS_MINI_SYSTEM
static void TransGetBleMac(const SessionParam *param, LaneRequestOption *requestOption)
{
    if (LnnGetRemoteStrInfo(requestOption->requestInfo.trans.networkId, STRING_KEY_BLE_MAC,
            requestOption->requestInfo.trans.peerBleMac, BT_MAC_LEN) != SOFTBUS_OK) {
        if (strcpy_s(requestOption->requestInfo.trans.peerBleMac, BT_MAC_LEN, "") != EOK) {
            TRANS_LOGE(TRANS_SVC, "strcpy fail");
        }
        TRANS_LOGW(TRANS_SVC, "requestOption get ble mac fail.");
    }
}
#endif

static int32_t GetRequestOptionBySessionParam(const SessionParam *param, LaneRequestOption *requestOption,
    bool *isQosLane)
{
    requestOption->type = LANE_TYPE_TRANS;
    if (memcpy_s(requestOption->requestInfo.trans.networkId, NETWORK_ID_BUF_LEN,
        param->peerDeviceId, NETWORK_ID_BUF_LEN) != EOK) {
        TRANS_LOGE(TRANS_SVC, "memcpy networkId failed.");
        return SOFTBUS_MEM_ERR;
    }

    LaneTransType transType = TransGetLaneTransTypeBySession(param);
    if (transType == LANE_T_BUTT) {
        return SOFTBUS_TRANS_INVALID_SESSION_TYPE;
    }
    requestOption->requestInfo.trans.networkDelegate = false;
    if (strcmp(param->sessionName, SESSION_NAME_PHONEPAD) == 0 ||
        strcmp(param->sessionName, SESSION_NAME_CASTPLUS) == 0) {
        requestOption->requestInfo.trans.networkDelegate = true;
    }
    requestOption->requestInfo.trans.p2pOnly = false;
    if (strcmp(param->sessionName, SESSION_NAME_DISTRIBUTE_COMMUNICATION) == 0 || IsShareSession(param->sessionName)) {
        requestOption->requestInfo.trans.p2pOnly = true;
    }
    requestOption->requestInfo.trans.transType = transType;
    requestOption->requestInfo.trans.expectedBw = 0; /* init expectBW */
    requestOption->requestInfo.trans.acceptableProtocols = LNN_PROTOCOL_ALL ^ LNN_PROTOCOL_NIP;
    TransGetQosInfo(param, &requestOption->requestInfo.trans.qosRequire, isQosLane);

    NodeInfo info;
    int32_t ret = LnnGetRemoteNodeInfoById(requestOption->requestInfo.trans.networkId, CATEGORY_NETWORK_ID, &info);
    if ((ret == SOFTBUS_OK) && LnnHasDiscoveryType(&info, DISCOVERY_TYPE_LSA)) {
        requestOption->requestInfo.trans.acceptableProtocols |= LNN_PROTOCOL_NIP;
    }
#ifdef SOFTBUS_MINI_SYSTEM
    // get ble mac only on mini system
    TransGetBleMac(param, requestOption);
#endif
    int32_t uid;
    ret = TransGetUidAndPid(param->sessionName, &uid, &(requestOption->requestInfo.trans.pid));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "transGetUidAndPid failed.");
        return ret;
    }

    TransformSessionPreferredToLanePreferred(param, &(requestOption->requestInfo.trans.expectedLink),
        &requestOption->requestInfo.trans);
    return SOFTBUS_OK;
}

static int32_t TransSoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, uint32_t timeMillis)
{
#define CONVERSION_BASE 1000LL
    if (timeMillis == 0) {
        return SoftBusCondWait(cond, mutex, NULL);
    }

    SoftBusSysTime now;
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans softbus get time failed.");
        return SOFTBUS_ERR;
    }
    int64_t usTime = now.sec * CONVERSION_BASE * CONVERSION_BASE + now.usec + timeMillis * CONVERSION_BASE;
    SoftBusSysTime tv;
    tv.sec = usTime / CONVERSION_BASE / CONVERSION_BASE;
    tv.usec = usTime % (CONVERSION_BASE * CONVERSION_BASE);
    TRANS_LOGI(TRANS_SVC, "start wait cond endSecond=%{public}" PRId64, tv.sec);
    return SoftBusCondWait(cond, mutex, &tv);
}

static int32_t TransWaitingRequestCallback(uint32_t laneId)
{
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane request list hasn't init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    bool isFound = false;
    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (item->laneId == laneId) {
            isFound = true;
            break;
        }
    }
    if (!isFound) {
        (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
        TRANS_LOGI(TRANS_SVC, "not found laneId in pending. laneId=%{public}u", laneId);
        return SOFTBUS_ERR;
    }
    if (item->isFinished == false) {
        int32_t rc = TransSoftBusCondWait(&item->cond, &g_reqLanePendingList->lock, 0);
        if (rc != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            TRANS_LOGI(TRANS_SVC, "wait cond failed laneId=%{public}u", laneId);
            return rc;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    TRANS_LOGI(TRANS_SVC, "receive lane cond laneId=%{public}u", laneId);
    return SOFTBUS_OK;
}

static int32_t TransAddLaneReqToPendingAndWaiting(bool isQosLane, uint32_t laneId,
    const LaneRequestOption *requestOption)
{
    if (requestOption == NULL) {
        TRANS_LOGE(TRANS_SVC, "param error.");
        return SOFTBUS_ERR;
    }

    int32_t ret = TransAddLaneReqFromPendingList(laneId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "add laneId to pending failed. laneId=%{public}u", laneId);
        return SOFTBUS_ERR;
    }

    ILaneListener listener;
    listener.OnLaneRequestSuccess = TransOnLaneRequestSuccess;
    listener.OnLaneRequestFail = TransOnLaneRequestFail;
    listener.OnLaneStateChange = TransOnLaneStateChange;
    if (isQosLane) {
        // lane by qos
        ret = GetLaneManager()->lnnRequestLane(laneId, requestOption, &listener);
    } else {
        ret = LnnRequestLane(laneId, requestOption, &listener);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans request lane failed.");
        (void)TransDelLaneReqFromPendingList(laneId);
        return SOFTBUS_ERR;
    }
    TRANS_LOGI(TRANS_SVC, "add laneId to pending and start waiting. laneId=%{public}u", laneId);
    if (TransWaitingRequestCallback(laneId) != SOFTBUS_OK) {
        (void)TransDelLaneReqFromPendingList(laneId);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransGetLaneInfoByOption(bool isQosLane, const LaneRequestOption *requestOption, LaneConnInfo *connInfo,
    uint32_t *laneId)
{
    if ((requestOption == NULL) || (connInfo == NULL) || (laneId == NULL)) {
        TRANS_LOGE(TRANS_SVC, "get lane info by option param error.");
        return SOFTBUS_ERR;
    }

    *laneId = GetLaneManager()->applyLaneId(LANE_TYPE_TRANS);
    if (TransAddLaneReqToPendingAndWaiting(isQosLane, *laneId, requestOption) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans add lane to pending list failed.");
        return SOFTBUS_ERR;
    }
    bool bSuccess = false;
    int32_t errCode = SOFTBUS_ERR;
    if (TransGetLaneReqItemByLaneId(*laneId, &bSuccess, connInfo, &errCode) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane req item failed. laneId=%{public}u.", *laneId);
        (void)TransDelLaneReqFromPendingList(*laneId);
        return SOFTBUS_ERR;
    }

    int32_t ret = SOFTBUS_OK;
    if (!bSuccess) {
        ret = errCode;
        TRANS_LOGE(TRANS_SVC, "request lane conninfo failed. laneId=%{public}u.", *laneId);
    }
    TRANS_LOGI(TRANS_SVC, "request lane conninfo success. laneId=%{public}u.", *laneId);
    (void)TransDelLaneReqFromPendingList(*laneId);
    return ret;
}

int32_t TransGetLaneInfo(const SessionParam *param, LaneConnInfo *connInfo, uint32_t *laneId)
{
    if ((param == NULL) || (connInfo == NULL) || (laneId == NULL)) {
        TRANS_LOGE(TRANS_SVC, "get lane info param error.");
        return SOFTBUS_INVALID_PARAM;
    }

    LaneRequestOption requestOption;
    (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
    bool isQosLane = false;
    if (GetRequestOptionBySessionParam(param, &requestOption, &isQosLane) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    int32_t ret = TransGetLaneInfoByOption(isQosLane, &requestOption, connInfo, laneId);
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = NULL,
        .socketName = param->sessionName,
        .laneId = *laneId,
        .peerNetworkId = param->peerDeviceId,
        .laneTransType = requestOption.requestInfo.trans.transType,
        .errcode = ret,
        .result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_SELECT_LANE, extra);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane info by option failed.");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t SetP2pConnInfo(const P2pConnInfo *p2pInfo, ConnectOption *connOpt)
{
    TRANS_LOGI(TRANS_SVC, "set p2p conn info.");
    connOpt->type = CONNECT_P2P;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), p2pInfo->peerIp) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set p2p localIp err");
        return SOFTBUS_MEM_ERR;
    }
    connOpt->socketOption.protocol = LNN_PROTOCOL_IP;
    connOpt->socketOption.port = -1;
    return SOFTBUS_OK;
}
static int32_t SetP2pReusesConnInfo(const WlanConnInfo *connInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_P2P_REUSE;
    connOpt->socketOption.port = (int32_t)connInfo->port;
    connOpt->socketOption.protocol = connInfo->protocol;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), connInfo->addr) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set p2p reuse localIp err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetWlanConnInfo(const WlanConnInfo *connInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_TCP;
    connOpt->socketOption.port = (int32_t)connInfo->port;
    connOpt->socketOption.protocol = connInfo->protocol;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), connInfo->addr) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set wlan localIp err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetBrConnInfo(const BrConnInfo *brInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_BR;
    if (strcpy_s(connOpt->brOption.brMac, sizeof(connOpt->brOption.brMac),
            brInfo->brMac) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set br mac err");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t SetBleConnInfo(const BleConnInfo *bleInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_BLE;
    if (strcpy_s(connOpt->bleOption.bleMac, sizeof(connOpt->bleOption.bleMac),
            bleInfo->bleMac) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set ble mac err");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(connOpt->bleOption.deviceIdHash, sizeof(connOpt->bleOption.deviceIdHash),
            bleInfo->deviceIdHash, sizeof(bleInfo->deviceIdHash)) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set deviceId hash err");
        return SOFTBUS_ERR;
    }
    connOpt->bleOption.protocol = bleInfo->protoType;
    connOpt->bleOption.psm = bleInfo->psm;
    connOpt->bleOption.fastestConnectEnable = true;
    return SOFTBUS_OK;
}

static int32_t SetBleDirectConnInfo(const BleDirectConnInfo *bleDirect, ConnectOption *connOpt)
{
    if (strcpy_s(connOpt->bleDirectOption.networkId, NETWORK_ID_BUF_LEN, bleDirect->networkId) != EOK) {
        TRANS_LOGW(TRANS_SVC, "set networkId err.");
        return SOFTBUS_MEM_ERR;
    }
    connOpt->type = CONNECT_BLE_DIRECT;
    connOpt->bleDirectOption.protoType = bleDirect->protoType;
    return SOFTBUS_OK;
}

static int32_t SetHmlConnectInfo(const P2pConnInfo *p2pInfo, ConnectOption *connOpt)
{
    TRANS_LOGI(TRANS_SVC, "set hml conn info.");
    connOpt->type = CONNECT_HML;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), p2pInfo->peerIp) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set hml localIp err");
        return SOFTBUS_MEM_ERR;
    }
    connOpt->socketOption.protocol = LNN_PROTOCOL_IP;
    connOpt->socketOption.port = -1;
    return SOFTBUS_OK;
}

int32_t TransGetConnectOptByConnInfo(const LaneConnInfo *info, ConnectOption *connOpt)
{
    if (info == NULL || connOpt == NULL) {
        TRANS_LOGW(TRANS_SVC, "invalid param.");
        return SOFTBUS_ERR;
    }
    if (info->type == LANE_P2P || info->type == LANE_HML) {
        return SetP2pConnInfo(&(info->connInfo.p2p), connOpt);
    } else if (info->type == LANE_WLAN_2P4G || info->type == LANE_WLAN_5G || info->type == LANE_ETH) {
        return SetWlanConnInfo(&(info->connInfo.wlan), connOpt);
    } else if (info->type == LANE_BR) {
        return SetBrConnInfo(&(info->connInfo.br), connOpt);
    } else if ((info->type == LANE_BLE) || (info->type == LANE_COC)) {
        return SetBleConnInfo(&(info->connInfo.ble), connOpt);
    } else if (info->type == LANE_P2P_REUSE) {
        return SetP2pReusesConnInfo(&(info->connInfo.wlan), connOpt);
    } else if (info->type == LANE_BLE_DIRECT || info->type == LANE_COC_DIRECT) {
        return SetBleDirectConnInfo(&(info->connInfo.bleDirect), connOpt);
    } else if (info->type == LANE_HML) {
        return SetHmlConnectInfo(&(info->connInfo.p2p), connOpt);
    }

    TRANS_LOGE(TRANS_SVC, "get conn opt err: type=%{public}d", info->type);
    return SOFTBUS_ERR;
}

bool TransGetAuthTypeByNetWorkId(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "GetAuthType fail, ret=%{public}d", ret);
        return false;
    }
    return ((uint32_t)value == (1 << ONLINE_METANODE)) ? true : false;
}