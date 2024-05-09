/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "lnn_lane_reliability.h"

#include <securec.h>
#include <string.h>
#include "lnn_lane_link.h"
#include "lnn_log.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_socket.h"

#define WLAN_DETECT_TIMEOUT 3000

typedef struct {
    ListNode node;
    LaneLinkInfo link;
    uint32_t laneReqId;
    LaneLinkCb cb;
    union {
        uint32_t wlanFd;
    } connId;
    uint32_t laneDetectId;
} LaneDetectInfo;

static SoftBusList g_laneDetectList;

static int32_t GetSameLaneDetectInfo(LaneDetectInfo *infoItem)
{
    if (SoftBusMutexLock(&g_laneDetectList.lock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LaneDetectInfo *item = NULL;
    LaneDetectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneDetectList.list, LaneDetectInfo, node) {
        switch (infoItem->link.type) {
            case LANE_WLAN_2P4G:
            case LANE_WLAN_5G:
                if ((strncmp(infoItem->link.linkInfo.wlan.connInfo.addr,
                    item->link.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN) == 0) &&
                    (infoItem->link.linkInfo.wlan.connInfo.port ==
                    item->link.linkInfo.wlan.connInfo.port)) {
                    infoItem->connId.wlanFd = item->connId.wlanFd;
                    infoItem->laneDetectId = item->laneDetectId;
                    ListTailInsert(&g_laneDetectList.list, &infoItem->node);
                    SoftBusMutexUnlock(&g_laneDetectList.lock);
                    return SOFTBUS_OK;
                }
                break;
            default:
                break;
        }
    }
    SoftBusMutexUnlock(&g_laneDetectList.lock);
    return SOFTBUS_ERR;
}

static int32_t ClientConnectTcp(LaneDetectInfo *infoItem)
{
    ConnectOption option = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = infoItem->link.linkInfo.wlan.connInfo.port,
            .moduleId = LANE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    if (strncpy_s(option.socketOption.addr, MAX_SOCKET_ADDR_LEN,
        infoItem->link.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    int32_t fd = ConnOpenClientSocket(&option, BIND_ADDR_ALL, true);
    if (fd < 0) {
        return SOFTBUS_CONN_FAIL;
    }
    return fd;
}

static void DelLaneDetectInfo(uint32_t detectId)
{
    if (SoftBusMutexLock(&g_laneDetectList.lock) != SOFTBUS_OK) {
        return;
    }
    LaneDetectInfo *item = NULL;
    LaneDetectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneDetectList.list, LaneDetectInfo, node) {
        if (item->laneDetectId == detectId) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    SoftBusMutexUnlock(&g_laneDetectList.lock);
}

static int32_t GetLaneDetectInfoByWlanFd(uint32_t fd, LaneDetectInfo *infoItem)
{
    if (SoftBusMutexLock(&g_laneDetectList.lock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LaneDetectInfo *item = NULL;
    LaneDetectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneDetectList.list, LaneDetectInfo, node) {
        if (item->connId.wlanFd == fd) {
            if (memcpy_s(infoItem, sizeof(LaneDetectInfo), item,
                sizeof(LaneDetectInfo)) != EOK) {
                SoftBusMutexUnlock(&g_laneDetectList.lock);
                return SOFTBUS_MEM_ERR;
            }
            SoftBusMutexUnlock(&g_laneDetectList.lock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&g_laneDetectList.lock);
    return SOFTBUS_ERR;
}

static int32_t AddLaneTriggerAndTimeOut(int32_t fd, uint32_t detectId)
{
    int32_t ret = PostDetectTimeoutMessage(detectId, WLAN_DETECT_TIMEOUT);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wlan detect post timeout message fail, detectId=%{public}u", detectId);
        return ret;
    }
    ret = AddTrigger(LANE, fd, WRITE_TRIGGER);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wlan detect add trigger fail, detectId=%{public}u, fd=%{public}d", detectId, fd);
        RemoveDetectTimeoutMessage(detectId);
        return ret;
    }
    return SOFTBUS_OK;
}

static uint32_t g_ReqId = 0;

static uint32_t GetLaneDetectIdWithoutLock()
{
#define REQID_MAX 1000000
    g_ReqId = g_ReqId % REQID_MAX + 1;
    uint32_t reqId = g_ReqId;
    return reqId;
}

static int32_t WlanDetectReliability(uint32_t laneReqId, const LaneLinkInfo *laneInfo, const LaneLinkCb *callback)
{
    LaneDetectInfo *infoItem = (LaneDetectInfo *)SoftBusMalloc(sizeof(LaneDetectInfo));
    if (infoItem == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    infoItem->laneReqId = laneReqId;
    if (memcpy_s(&infoItem->cb, sizeof(LaneLinkCb), callback, sizeof(LaneLinkCb)) != EOK) {
        SoftBusFree(infoItem);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(&(infoItem->link), sizeof(LaneLinkInfo), laneInfo, sizeof(LaneLinkInfo)) != EOK) {
        SoftBusFree(infoItem);
        return SOFTBUS_MEM_ERR;
    }
    if (GetSameLaneDetectInfo(infoItem) == SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "wlan reuse detectId=%{public}u, laneReqId=%{public}u", infoItem->laneDetectId,
            infoItem->laneReqId);
        return SOFTBUS_OK;
    }
    int32_t fd = ClientConnectTcp(infoItem);
    if (fd < 0) {
        LNN_LOGE(LNN_LANE, "wlan detect connect fail, port=%{public}d, laneReqId=%{public}u",
            infoItem->link.linkInfo.wlan.connInfo.port, infoItem->laneReqId);
        SoftBusFree(infoItem);
        return fd;
    }
    infoItem->connId.wlanFd = fd;
    if (SoftBusMutexLock(&g_laneDetectList.lock) != SOFTBUS_OK) {
        ConnShutdownSocket(fd);
        SoftBusFree(infoItem);
        return SOFTBUS_LOCK_ERR;
    }
    infoItem->laneDetectId = GetLaneDetectIdWithoutLock();
    ListTailInsert(&g_laneDetectList.list, &infoItem->node);
    SoftBusMutexUnlock(&g_laneDetectList.lock);
    int32_t ret = AddLaneTriggerAndTimeOut(fd, infoItem->laneDetectId);
    if (ret != SOFTBUS_OK) {
        ConnShutdownSocket(fd);
        DelLaneDetectInfo(infoItem->laneDetectId);
        LNN_LOGI(LNN_LANE, "wlan add trigger and timrout msg fail, laneReqId=%{public}u", infoItem->laneDetectId);
        return ret;
    }
    LNN_LOGI(LNN_LANE, "wlan first detectId=%{public}u, fd=%{public}d, laneReqId=%{public}u",
        infoItem->laneDetectId, fd, infoItem->laneReqId);
    return SOFTBUS_OK;
}

int32_t LaneDetectFload(const LaneResource *resourceItem)
{
    (void)resourceItem;
    return SOFTBUS_OK;
}

static int32_t LaneDetectOnConnectEvent(ListenerModule module, int32_t cfd, const ConnectOption *clientAddr)
{
    (void)module;
    (void)cfd;
    (void)clientAddr;
    return SOFTBUS_OK;
}

static int32_t GetAllDetectInfoWithDetectId(uint32_t detectId, ListNode *detectInfoList)
{
    LNN_LOGI(LNN_LANE, "get all detect info, detectId=%{public}u", detectId);
    if (SoftBusMutexLock(&g_laneDetectList.lock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LaneDetectInfo *item = NULL;
    LaneDetectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneDetectList.list, LaneDetectInfo, node) {
        if (item->laneDetectId == detectId) {
            ListDelete(&item->node);
            ListTailInsert(detectInfoList, &item->node);
        }
    }
    SoftBusMutexUnlock(&g_laneDetectList.lock);
    return SOFTBUS_OK;
}

static int32_t NotifyWlanDetectResult(LaneDetectInfo *requestItem, bool isSendSuc)
{
    ListNode detectInfoList;
    ListInit(&detectInfoList);
    int32_t ret = GetAllDetectInfoWithDetectId(requestItem->laneDetectId, &detectInfoList);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get all detect info fail, laneDetectId=%{public}u", requestItem->laneDetectId);
        return ret;
    }
    LaneDetectInfo *item = NULL;
    LaneDetectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &detectInfoList, LaneDetectInfo, node) {
        if (!isSendSuc) {
            LNN_LOGI(LNN_LANE, "Detect failed, wlan=%{public}d, laneReqId=%{public}u, detectId=%{public}u",
                item->link.type, item->laneReqId, requestItem->laneDetectId);
            item->cb.OnLaneLinkFail(item->laneReqId, SOFTBUS_CONN_FAIL, item->link.type);
        } else {
            LaneLinkInfo laneInfo;
            (void)memset_s(&laneInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
            if (memcpy_s(&laneInfo, sizeof(LaneLinkInfo), &(item->link), sizeof(LaneLinkInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "memcpy linkinfo failed, laneReqId=%{public}u", item->laneReqId);
                ListDelete(&item->node);
                SoftBusFree(item);
                continue;
            }
            LNN_LOGI(LNN_LANE, "Detect success, wlan=%{public}d, laneReqId=%{public}u, detectId=%{public}u",
                item->link.type, item->laneReqId, requestItem->laneDetectId);
            item->cb.OnLaneLinkSuccess(item->laneReqId, laneInfo.type, &laneInfo);
        }
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    return SOFTBUS_OK;
}

static int32_t LaneDetectOnDataEvent(ListenerModule module, int32_t events, int32_t fd)
{
    if (module != LANE) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (events == SOFTBUS_SOCKET_OUT) {
        LaneDetectInfo requestItem;
        (void)memset_s(&requestItem, sizeof(LaneDetectInfo), 0, sizeof(LaneDetectInfo));
        if (GetLaneDetectInfoByWlanFd(fd, &requestItem) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "wlan detect info not found by fd=%{public}d", fd);
            (void)DelTrigger(LANE, fd, WRITE_TRIGGER);
            ConnShutdownSocket(fd);
            return SOFTBUS_NOT_FIND;
        }
        LNN_LOGI(LNN_LANE, "wlan connect success, detectId=%{public}u, fd=%{public}d", requestItem.laneDetectId, fd);
        (void)DelTrigger(LANE, fd, WRITE_TRIGGER);
        char buf[] = "lanedetect";
        ssize_t len = ConnSendSocketData(fd, buf, sizeof(buf), 0);
        bool isSendSuc = (len == sizeof(buf)) ? true : false;
        ConnShutdownSocket(fd);
        RemoveDetectTimeoutMessage(requestItem.laneDetectId);
        int32_t ret = NotifyWlanDetectResult(&requestItem, isSendSuc);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "wlan notify detect result fail, detectId=%{public}u", requestItem.laneDetectId);
            return ret;
        }
    } else if (events == SOFTBUS_SOCKET_EXCEPTION) {
        LNN_LOGE(LNN_LANE, "wlan detect socket exception, fd=%{public}d", fd);
        (void)DelTrigger(LANE, fd, WRITE_TRIGGER);
        ConnShutdownSocket(fd);
    }
    return SOFTBUS_OK;
}

int32_t LaneDetectReliability(uint32_t laneReqId, const LaneLinkInfo *laneInfo, const LaneLinkCb *callback)
{
    if (laneReqId == INVALID_LANE_REQ_ID || laneInfo == NULL || callback == NULL) {
        LNN_LOGE(LNN_LANE, "invalid input parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_LANE, "lane detect start, linktype=%{public}d, laneReqId=%{public}u", laneInfo->type, laneReqId);
    int32_t result = SOFTBUS_ERR;
    switch (laneInfo->type) {
        case LANE_WLAN_2P4G:
        case LANE_WLAN_5G:
            result = WlanDetectReliability(laneReqId, laneInfo, callback);
            break;
        default:
            break;
    }
    return result;
}

void NotifyDetectTimeout(uint32_t detectId)
{
    ListNode detectInfoList;
    ListInit(&detectInfoList);
    if (GetAllDetectInfoWithDetectId(detectId, &detectInfoList) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get all detect info fail, detectId=%{public}u", detectId);
        return;
    }
    LaneDetectInfo *item = NULL;
    LaneDetectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &detectInfoList, LaneDetectInfo, node) {
        LNN_LOGI(LNN_LANE, "Detect time out, link=%{public}d, laneReqId=%{public}u, detectId=%{public}u",
            item->link.type, item->laneReqId, item->laneDetectId);
        item->cb.OnLaneLinkFail(item->laneReqId, SOFTBUS_LANE_DETECT_FAIL, item->link.type);
        ListDelete(&item->node);
        SoftBusFree(item);
    }
}

int32_t InitLaneReliability(void)
{
    SoftbusBaseListener listener = {
        .onConnectEvent = LaneDetectOnConnectEvent,
        .onDataEvent = LaneDetectOnDataEvent,
    };
    if (StartBaseClient(LANE, &listener) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "listening fail, moudle=%{public}d ", LANE);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_laneDetectList.lock, NULL) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    ListInit(&g_laneDetectList.list);
    g_laneDetectList.cnt = 0;
    return SOFTBUS_OK;
}
