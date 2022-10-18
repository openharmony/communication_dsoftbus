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
#include <unistd.h>
#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_session_manager.h"

#define TRANS_REQUEST_PENDING_TIMEOUT (5000)

typedef struct {
    ListNode node;
    uint32_t laneId;
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
    if (g_reqLanePendingList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_reqLanePendingList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed.");
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "del tran request from pending [lane=%u].", laneId);
    if (g_reqLanePendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lane request list hasn't initialized.");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *laneItem = NULL;
    TransReqLaneItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (laneItem->laneId == laneId) {
            (void)SoftBusCondDestroy(&laneItem->cond);
            ListDelete(&(laneItem->node));
            g_reqLanePendingList->cnt--;
            SoftBusFree(laneItem);
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane request not found, [laneId=%u].", laneId);
    return SOFTBUS_ERR;
}

static int32_t TransAddLaneReqFromPendingList(uint32_t laneId)
{
    if (g_reqLanePendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lane pending list no initialized.");
        return SOFTBUS_ERR;
    }

    TransReqLaneItem *item = (TransReqLaneItem *)SoftBusCalloc(sizeof(TransReqLaneItem));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc lane request item err.");
        return SOFTBUS_MALLOC_ERR;
    }
    item->laneId = laneId;
    item->bSucc = false;
    item->isFinished = false;
    (void)memset_s(&(item->connInfo), sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));

    if (SoftBusMutexLock(&g_reqLanePendingList->lock) != SOFTBUS_OK) {
        SoftBusFree(item);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (SoftBusCondInit(&item->cond) != 0) {
        SoftBusFree(item);
        (void)SoftBusMutexUnlock(&g_reqLanePendingList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cond init failed.");
        return SOFTBUS_ERR;
    }
    ListInit(&(item->node));
    ListAdd(&(g_reqLanePendingList->list), &(item->node));
    g_reqLanePendingList->cnt++;
    (void)SoftBusMutexUnlock(&g_reqLanePendingList->lock);

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "add tran request to pending [lane=%u].", laneId);
    return SOFTBUS_OK;
}

static int32_t TransGetLaneReqItemByLaneId(uint32_t laneId, bool *bSucc, LaneConnInfo *connInfo)
{
    if (bSucc == NULL || connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "param err.");
        return SOFTBUS_ERR;
    }
    if (g_reqLanePendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lane request list hasn't initialized.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (item->laneId == laneId) {
            *bSucc = item->bSucc;
            if (memcpy_s(connInfo, sizeof(LaneConnInfo), &(item->connInfo), sizeof(LaneConnInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane request not found.[laneId=%u].", laneId);
    return SOFTBUS_ERR;
}

static int32_t TransUpdateLaneConnInfoByLaneId(uint32_t laneId, bool bSucc, const LaneConnInfo *connInfo)
{
    if (g_reqLanePendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lane request list hasn't initialized.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (item->laneId == laneId) {
            item->bSucc = bSucc;
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane request not found.[laneId=%u].", laneId);
    return SOFTBUS_ERR;
}

static void TransOnLaneRequestSuccess(uint32_t laneId, const LaneConnInfo *connInfo)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans on lane[%u] request success.", laneId);
    if (TransUpdateLaneConnInfoByLaneId(laneId, true, connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "update lane connInfo failed, id[%u].", laneId);
    }
    return;
}

static void TransOnLaneRequestFail(uint32_t laneId, LaneRequestFailReason reason)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans on lane[%u] request failed, reason[%u].", laneId, reason);
    if (TransUpdateLaneConnInfoByLaneId(laneId, false, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "update lane connInfo failed, id[%u].", laneId);
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
    if (param == NULL) {
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

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "session type:[%u] no support.", type);
    return LANE_T_BUTT;
}

static LaneLinkType TransGetLaneLinkTypeBySessionLinkType(LinkType type)
{
    switch (type) {
        case LINK_TYPE_WIFI_WLAN_5G:
            return LANE_WLAN_5G;
        case LINK_TYPE_WIFI_WLAN_2G:
            return LANE_WLAN_2P4G;
        case LINK_TYPE_WIFI_P2P:
            return LANE_P2P;
        case LINK_TYPE_BR:
            return LANE_BR;
        default:
            break;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session invalid link type[%d].", type);
    return LANE_LINK_TYPE_BUTT;
}

static void TransformSessionPreferredToLanePreferred(const SessionParam *param, LanePreferredLinkList *preferred)
{
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
        if (preferred->linkTypeNum >= LANE_LINK_TYPE_BUTT) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "session preferred linknum override lane maxcnt:%d.", LANE_LINK_TYPE_BUTT);
            break;
        }
        preferred->linkType[preferred->linkTypeNum] = linkType;
        preferred->linkTypeNum += 1;
    }
    return;
}

static int32_t GetRequestOptionBySessionParam(const SessionParam *param, LaneRequestOption *requestOption)
{
    requestOption->type = LANE_TYPE_TRANS;
    if (memcpy_s(requestOption->requestInfo.trans.networkId, NETWORK_ID_BUF_LEN,
        param->peerDeviceId, NETWORK_ID_BUF_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy networkId failed.");
        return SOFTBUS_ERR;
        }

    LaneTransType transType = TransGetLaneTransTypeBySession(param);
    if (transType == LANE_T_BUTT) {
        return SOFTBUS_ERR;
    }

    requestOption->requestInfo.trans.transType = transType;
    requestOption->requestInfo.trans.expectedBw = 0; /* init expectBW */
    int32_t uid;
    if (TransGetUidAndPid(param->sessionName, &uid, &(requestOption->requestInfo.trans.pid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "transGetUidAndPid failed.");
        return SOFTBUS_ERR;
    }

    TransformSessionPreferredToLanePreferred(param, &(requestOption->requestInfo.trans.expectedLink));
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans softbus get time failed.");
        return SOFTBUS_ERR;
    }
    int64_t usTime = now.sec * CONVERSION_BASE * CONVERSION_BASE + now.usec + timeMillis * CONVERSION_BASE;
    SoftBusSysTime tv;
    tv.sec = usTime / CONVERSION_BASE / CONVERSION_BASE;
    tv.usec = usTime % (CONVERSION_BASE * CONVERSION_BASE);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "start wait cond endSecond:%lld.", tv.sec);
    return SoftBusCondWait(cond, mutex, &tv);
}

static int32_t TransWaitingRequestCallback(uint32_t laneId)
{
    if (g_reqLanePendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lane request list hasn't initialized.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    bool bFound = false;
    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (item->laneId == laneId) {
            bFound = true;
            break;
        }
    }
    if (!bFound) {
        (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "not found lane[%u] in pending.", laneId);
        return SOFTBUS_ERR;
    }
    if (item->isFinished == false) {
        int32_t rc = TransSoftBusCondWait(&item->cond, &g_reqLanePendingList->lock, 0);
        if (rc != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "wait cond failed laneId[%u].", laneId);
            return rc;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "receive lane cond laneId[%u].", laneId);
    return SOFTBUS_OK;
}

static int32_t TransAddLaneReqToPendingAndWaiting(uint32_t laneId, const LaneRequestOption *requestOption)
{
    if (requestOption == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "param error.");
        return SOFTBUS_ERR;
    }

    int32_t ret = TransAddLaneReqFromPendingList(laneId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add lane[%u] to pending failed.", laneId);
        return SOFTBUS_ERR;
    }

    ILaneListener listener;
    listener.OnLaneRequestSuccess = TransOnLaneRequestSuccess;
    listener.OnLaneRequestFail = TransOnLaneRequestFail;
    listener.OnLaneStateChange = TransOnLaneStateChange;
    if (LnnRequestLane(laneId, requestOption, &listener) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans request lane failed.");
        (void)TransDelLaneReqFromPendingList(laneId);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "add lane[%u] to pending and start waiting.", laneId);
    if (TransWaitingRequestCallback(laneId) != SOFTBUS_OK) {
        (void)TransDelLaneReqFromPendingList(laneId);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransGetLaneInfoByOption(const LaneRequestOption *requestOption, LaneConnInfo *connInfo, uint32_t *laneId)
{
    if ((requestOption == NULL) || (connInfo == NULL) || (laneId == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get lane info by option param error.");
        return SOFTBUS_ERR;
    }

    *laneId = ApplyLaneId(LANE_TYPE_TRANS);
    if (*laneId <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans apply lane failed.");
        return SOFTBUS_ERR;
    }
    if (TransAddLaneReqToPendingAndWaiting(*laneId, requestOption) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans add lane to pending list failed.");
        return SOFTBUS_ERR;
    }
    bool bSuccess = false;
    if (TransGetLaneReqItemByLaneId(*laneId, &bSuccess, connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get lane req item failed. id[%u].", *laneId);
        (void)TransDelLaneReqFromPendingList(*laneId);
        return SOFTBUS_ERR;
    }

    int32_t ret = SOFTBUS_OK;
    if (!bSuccess) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "request lane conninfo failed. id[%u].", *laneId);
        ret = SOFTBUS_ERR;
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "request lane conninfo success. id[%u].", *laneId);
    }
    (void)TransDelLaneReqFromPendingList(*laneId);
    return ret;
}

int32_t TransGetLaneInfo(const SessionParam *param, LaneConnInfo *connInfo, uint32_t *laneId)
{
    if ((param == NULL) || (connInfo == NULL) || (laneId == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get lane info param error.");
        return SOFTBUS_ERR;
    }

    LaneRequestOption requestOption;
    (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
    if (GetRequestOptionBySessionParam(param, &requestOption) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    int32_t ret = TransGetLaneInfoByOption(&requestOption, connInfo, laneId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get lane info by option failed.");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t SetP2pConnInfo(const P2pConnInfo *p2pInfo, ConnectOption *connOpt)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "set p2p conn info.");
    connOpt->type = CONNECT_P2P;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), p2pInfo->peerIp) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set p2p localIp err");
        return SOFTBUS_MEM_ERR;
    }
    connOpt->socketOption.protocol = LNN_PROTOCOL_IP;
    connOpt->socketOption.port = -1;
    return SOFTBUS_OK;
}

static int32_t SetWlanConnInfo(const WlanConnInfo *connInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_TCP;
    connOpt->socketOption.port = (int32_t)connInfo->port;
    connOpt->socketOption.protocol = connInfo->protocol;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), connInfo->addr) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set wlan localIp err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetBrConnInfo(const BrConnInfo *brInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_BR;
    if (strcpy_s(connOpt->brOption.brMac, sizeof(connOpt->brOption.brMac),
            brInfo->brMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set br mac err");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t SetBleConnInfo(const BleConnInfo *bleInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_BLE;
    if (strcpy_s(connOpt->bleOption.bleMac, sizeof(connOpt->bleOption.bleMac),
            bleInfo->bleMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set ble mac err");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransGetConnectOptByConnInfo(const LaneConnInfo *info, ConnectOption *connOpt)
{
    if (info == NULL || connOpt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
        return SOFTBUS_ERR;
    }
    if (info->type == LANE_P2P) {
        return SetP2pConnInfo(&(info->connInfo.p2p), connOpt);
    } else if (info->type == LANE_WLAN_2P4G || info->type == LANE_WLAN_5G || info->type == LANE_ETH) {
        return SetWlanConnInfo(&(info->connInfo.wlan), connOpt);
    } else if (info->type == LANE_BR) {
        return SetBrConnInfo(&(info->connInfo.br), connOpt);
    } else if (info->type == LANE_BLE) {
        return SetBleConnInfo(&(info->connInfo.ble), connOpt);
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get conn opt err: type=%d", info->type);
    return SOFTBUS_ERR;
}

bool TransGetAuthTypeByNetWorkId(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthType fail, ret=%d", ret);
        return false;
    }
    return ((1 << ONLINE_METANODE) == (uint32_t)value) ? true : false;
}