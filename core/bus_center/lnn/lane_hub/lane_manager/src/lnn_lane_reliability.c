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
#define BT_DETECT_TIMEOUT 5000

typedef struct {
    WlanLinkInfo wlanInfo;
    uint32_t wlanFd;
} WlanDetectInfo;

typedef struct {
    BrLinkInfo brInfo;
    int32_t brReqId;
} BrDetectInfo;


typedef struct {
    ListNode node;
    LaneLinkType type;
    uint32_t lnnReqId;
    LaneLinkCb cb;
    union {
        WlanDetectInfo wlanDetect;
        BrDetectInfo brDetect;
    } linkInfo;
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
        switch (infoItem->type) {
            case LANE_WLAN_2P4G:
            case LANE_WLAN_5G:
                if ((strncmp(infoItem->linkInfo.wlanDetect.wlanInfo.connInfo.addr,
                        item->linkInfo.wlanDetect.wlanInfo.connInfo.addr, MAX_SOCKET_ADDR_LEN) == 0) &&
                        (infoItem->linkInfo.wlanDetect.wlanInfo.connInfo.port ==
                        item->linkInfo.wlanDetect.wlanInfo.connInfo.port)) {
                    infoItem->linkInfo.wlanDetect.wlanFd = item->linkInfo.wlanDetect.wlanFd;
                    infoItem->laneDetectId = item->laneDetectId;
                    ListTailInsert(&g_laneDetectList.list, &infoItem->node);
                    SoftBusMutexUnlock(&g_laneDetectList.lock);
                    return SOFTBUS_OK;
                }
                break;
            case LANE_BR:
                if ((strncmp(infoItem->linkInfo.brDetect.brInfo.brMac,
                        item->linkInfo.brDetect.brInfo.brMac, BT_MAC_LEN) == 0)) {
                    infoItem->linkInfo.brDetect.brReqId = item->linkInfo.brDetect.brReqId;
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
            .port = infoItem->linkInfo.wlanDetect.wlanInfo.connInfo.port,
            .moduleId = LANE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    if (strncpy_s(option.socketOption.addr, MAX_SOCKET_ADDR_LEN,
            infoItem->linkInfo.wlanDetect.wlanInfo.connInfo.addr, MAX_SOCKET_ADDR_LEN) != EOK) {
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
        if (item->linkInfo.wlanDetect.wlanFd == fd) {
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
    if (PostDetectTimeoutMessage(detectId, WLAN_DETECT_TIMEOUT)) {
        LNN_LOGE(LNN_LANE, "wlan detect post timeout message fail, detectId=%{public}u", detectId);
        return SOFTBUS_ERR;
    }
    if (AddTrigger(LANE, fd, WRITE_TRIGGER) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wlan detect add trigger fail, detectId=%{public}u, fd=%{public}d", detectId, fd);
        RemoveDetectTimeoutMessage(detectId);
        return SOFTBUS_ERR;
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

static int32_t WlanDetectReliability(uint32_t lnnReqId, const LaneLinkInfo *laneInfo, const LaneLinkCb *callback)
{
    LaneDetectInfo *infoItem = (LaneDetectInfo *)SoftBusMalloc(sizeof(LaneDetectInfo));
    if (infoItem == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    infoItem->lnnReqId = lnnReqId;
    infoItem->type = laneInfo->type;
    if (memcpy_s(&infoItem->cb, sizeof(LaneLinkCb), callback, sizeof(LaneLinkCb)) != EOK) {
        SoftBusFree(infoItem);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(&(infoItem->linkInfo.wlanDetect.wlanInfo), sizeof(WlanLinkInfo),
            &(laneInfo->linkInfo.wlan), sizeof(WlanLinkInfo)) != EOK) {
        SoftBusFree(infoItem);
        return SOFTBUS_MEM_ERR;
    }
    if (GetSameLaneDetectInfo(infoItem) == SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "wlan reuse detect=%{public}u, lnnReqId=%{public}u", infoItem->laneDetectId,
            infoItem->lnnReqId);
        return SOFTBUS_OK;
    }
    int32_t fd = ClientConnectTcp(infoItem);
    if (fd < 0) {
        LNN_LOGE(LNN_LANE, "wlan detect connect fail, port=%{public}d, lnnReqId=%{public}u",
            infoItem->linkInfo.wlanDetect.wlanInfo.connInfo.port, infoItem->lnnReqId);
        SoftBusFree(infoItem);
        return SOFTBUS_ERR;
    }
    infoItem->linkInfo.wlanDetect.wlanFd = fd;
    if (SoftBusMutexLock(&g_laneDetectList.lock) != SOFTBUS_OK) {
        ConnShutdownSocket(fd);
        SoftBusFree(infoItem);
        return SOFTBUS_LOCK_ERR;
    }
    infoItem->laneDetectId = GetLaneDetectIdWithoutLock();
    ListTailInsert(&g_laneDetectList.list, &infoItem->node);
    SoftBusMutexUnlock(&g_laneDetectList.lock);
    if (AddLaneTriggerAndTimeOut(fd, infoItem->laneDetectId) != SOFTBUS_OK) {
        ConnShutdownSocket(fd);
        DelLaneDetectInfo(infoItem->laneDetectId);
        LNN_LOGI(LNN_LANE, "wlan add trigger and timrout msg fail, lnnReqId=%{public}u", infoItem->laneDetectId);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "wlan first detect=%{public}u, fd=%{public}d, lnnReqId=%{public}u", infoItem->laneDetectId, fd,
        infoItem->lnnReqId);
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
    if (GetAllDetectInfoWithDetectId(requestItem->laneDetectId, &detectInfoList) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get all detect info fail, laneDetectId=%{public}u", requestItem->laneDetectId);
        return SOFTBUS_ERR;
    }
    LaneDetectInfo *item = NULL;
    LaneDetectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &detectInfoList, LaneDetectInfo, node) {
        if (!isSendSuc) {
            LNN_LOGI(LNN_LANE, "Detect failed, wlan=%{public}d, lnnReqId=%{public}u, detect=%{public}u",
                item->type, item->lnnReqId, requestItem->laneDetectId);
            item->cb.OnLaneLinkFail(item->lnnReqId, SOFTBUS_CONN_FAIL);
        } else {
            LaneLinkInfo laneInfo;
            (void)memset_s(&laneInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
            laneInfo.type = item->type;
            if (memcpy_s(&(laneInfo.linkInfo.wlan), sizeof(WlanLinkInfo),
                    &(item->linkInfo.wlanDetect.wlanInfo), sizeof(WlanLinkInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "memcpy linkinfo failed, lnnReqId=%{public}u", item->lnnReqId);
                ListDelete(&item->node);
                SoftBusFree(item);
                continue;
            }
            LNN_LOGI(LNN_LANE, "Detect sueccess, wlan=%{public}d, lnnReqId=%{public}u, detect=%{public}u",
                item->type, item->lnnReqId, requestItem->laneDetectId);
            item->cb.OnLaneLinkSuccess(item->lnnReqId, &laneInfo);
        }
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    return SOFTBUS_OK;
}

static int32_t LaneDetectOnDataEvent(ListenerModule module, int32_t events, int32_t fd)
{
    if (module != LANE) {
        return SOFTBUS_ERR;
    }
    if (events == SOFTBUS_SOCKET_OUT) {
        LaneDetectInfo requestItem;
        (void)memset_s(&requestItem, sizeof(LaneDetectInfo), 0, sizeof(LaneDetectInfo));
        if (GetLaneDetectInfoByWlanFd(fd, &requestItem) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "wlan detect info not found by fd=%{public}d", fd);
            (void)DelTrigger(LANE, fd, WRITE_TRIGGER);
            ConnShutdownSocket(fd);
            return SOFTBUS_ERR;
        }
        LNN_LOGI(LNN_LANE, "wlan connect sueccess, detect=%{public}u, fd=%{public}d", requestItem.laneDetectId, fd);
        (void)DelTrigger(LANE, fd, WRITE_TRIGGER);
        char buf[] = "lanedetect";
        ssize_t ret = ConnSendSocketData(fd, buf, sizeof(buf), 0);
        bool isSendSuc = (ret == sizeof(buf)) ? true : false;
        ConnShutdownSocket(fd);
        RemoveDetectTimeoutMessage(requestItem.laneDetectId);
        if (NotifyWlanDetectResult(&requestItem, isSendSuc) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "wlan notify detect result fail, detect=%{public}u", requestItem.laneDetectId);
            return SOFTBUS_ERR;
        }
    } else if (events == SOFTBUS_SOCKET_EXCEPTION) {
        LNN_LOGE(LNN_LANE, "wlan detect socket exception, fd=%{public}d", fd);
        (void)DelTrigger(LANE, fd, WRITE_TRIGGER);
        ConnShutdownSocket(fd);
    }
    return SOFTBUS_OK;
}

int32_t LaneDetectReliability(uint32_t lnnReqId, const LaneLinkInfo *laneInfo, const LaneLinkCb *callback)
{
    if (lnnReqId== INVALID_LANE_ID || laneInfo == NULL || callback == NULL) {
        LNN_LOGE(LNN_LANE, "invalid input parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_LANE, "lane detect start, linktype=%{public}d, lnnReqId=%{public}u", laneInfo->type, lnnReqId);
    LaneResource laneResourceInfo;
    (void)memset_s(&laneResourceInfo, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLinkInfo(laneInfo, &laneResourceInfo) == SOFTBUS_OK) {
        if (laneResourceInfo.isReliable) {
            LNN_LOGI(LNN_LANE, "reuse existed link reliability, link=%{public}d, lnnReqId=%{public}u", laneInfo->type,
                lnnReqId);
            callback->OnLaneLinkSuccess(lnnReqId, laneInfo);
            return SOFTBUS_OK;
        }
    }
    int32_t result = SOFTBUS_ERR;
    switch (laneInfo->type) {
        case LANE_WLAN_2P4G:
        case LANE_WLAN_5G:
            result = WlanDetectReliability(lnnReqId, laneInfo, callback);
            break;
        case LANE_BR:
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
        LNN_LOGE(LNN_LANE, "get all detect info fail, detect=%{public}u", detectId);
        return;
    }
    LaneDetectInfo *item = NULL;
    LaneDetectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &detectInfoList, LaneDetectInfo, node) {
        LNN_LOGI(LNN_LANE, "Detect time out, link=%{public}d, lnnReqId=%{public}u, detect=%{public}u",
            item->type, item->lnnReqId, item->laneDetectId);
        item->cb.OnLaneLinkFail(item->lnnReqId, SOFTBUS_CONN_FAIL);
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
