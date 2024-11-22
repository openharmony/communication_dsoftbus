/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lnn_lane_link_conflict.h"

#include <securec.h>

#include "anonymizer.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_lane_link_wifi_direct.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_utils.h"

#define CONFLICT_INFO_TIMELINESS 30000
#define CONFLICT_SHORT_HASH_LEN_TMP 8

typedef enum {
    MSG_TYPE_CONFLICT_TIMELINESS = 0,
    MSG_TYPE_CONFLICT_BUTT,
} LinkConflictMsgType;

static SoftBusList g_linkConflictList;
static SoftBusHandler g_linkConflictLoopHandler;

static int32_t LinkConflictLock(void)
{
    return SoftBusMutexLock(&g_linkConflictList.lock);
}

static void LinkConflictUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_linkConflictList.lock);
}

static int32_t LinkConflictPostMsgToHandler(int32_t msgType, uint64_t param1, uint64_t param2,
    void *obj, uint64_t delayMillis)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_LANE, "calloc link conflict handler msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (g_linkConflictLoopHandler.looper == NULL) {
        LNN_LOGE(LNN_LANE, "linkConflictLoopHandler looper not init");
        SoftBusFree(msg);
        return SOFTBUS_NO_INIT;
    }
    msg->what = msgType;
    msg->arg1 = param1;
    msg->arg2 = param2;
    msg->handler = &g_linkConflictLoopHandler;
    msg->obj = obj;
    if (delayMillis == 0) {
        g_linkConflictLoopHandler.looper->PostMessage(g_linkConflictLoopHandler.looper, msg);
    } else {
        g_linkConflictLoopHandler.looper->PostMessageDelay(g_linkConflictLoopHandler.looper, msg, delayMillis);
    }
    return SOFTBUS_OK;
}

static int32_t PostConflictInfoTimelinessMsg(const DevIdentifyInfo *info, LinkConflictType conflictType)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyDevInfo = NULL;
    Anonymize(info->type == IDENTIFY_TYPE_UDID_HASH ? info->devInfo.udidHash : info->devInfo.peerDevId,
        &anonyDevInfo);
    LNN_LOGI(LNN_LANE, "post conflict info timeliness msg, identifyType=%{public}d, devInfo=%{public}s,"
        " conflictType=%{public}d", info->type, AnonymizeWrapper(anonyDevInfo), conflictType);
    AnonymizeFree(anonyDevInfo);
    LinkConflictInfo *conflictItem = (LinkConflictInfo *)SoftBusCalloc(sizeof(LinkConflictInfo));
    if (conflictItem == NULL) {
        LNN_LOGE(LNN_LANE, "calloc conflictItem fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(&conflictItem->identifyInfo, sizeof(DevIdentifyInfo), info, sizeof(DevIdentifyInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy identifyInfo fail");
        SoftBusFree(conflictItem);
        return SOFTBUS_MEM_ERR;
    }
    conflictItem->conflictType = conflictType;
    int32_t ret = LinkConflictPostMsgToHandler(MSG_TYPE_CONFLICT_TIMELINESS, 0, 0,
        conflictItem, CONFLICT_INFO_TIMELINESS);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post link conflict msg fail");
        SoftBusFree(conflictItem);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t RemoveConflictInfoTimeliness(const SoftBusMessage *msg, void *data)
{
    if (msg == NULL || msg->obj == NULL || data == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LinkConflictInfo *srcInfo = (LinkConflictInfo*)msg->obj;
    LinkConflictInfo *dstInfo = (LinkConflictInfo*)data;
    if (msg->what != MSG_TYPE_CONFLICT_TIMELINESS) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (srcInfo->conflictType == dstInfo->conflictType &&
        memcmp(&srcInfo->identifyInfo, &dstInfo->identifyInfo, sizeof(DevIdentifyInfo)) == 0) {
        LNN_LOGI(LNN_LANE, "remove timeliness msg succ");
        SoftBusFree(srcInfo);
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

void RemoveConflictInfoTimelinessMsg(const DevIdentifyInfo *inputInfo, LinkConflictType conflictType)
{
    if (inputInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    char *anonyDevInfo = NULL;
    Anonymize(inputInfo->type == IDENTIFY_TYPE_UDID_HASH ?
        inputInfo->devInfo.udidHash : inputInfo->devInfo.peerDevId, &anonyDevInfo);
    LNN_LOGI(LNN_LANE, "remove timeliness msg, identifyType=%{public}d, devInfo=%{public}s, conflictType=%{public}d",
        inputInfo->type, AnonymizeWrapper(anonyDevInfo), conflictType);
    AnonymizeFree(anonyDevInfo);
    LinkConflictInfo conflictItem;
    (void)memset_s(&conflictItem, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    if (memcpy_s(&conflictItem.identifyInfo, sizeof(DevIdentifyInfo), inputInfo, sizeof(DevIdentifyInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy identifyInfo fail");
        return;
    }
    conflictItem.conflictType = conflictType;
    g_linkConflictLoopHandler.looper->RemoveMessageCustom(g_linkConflictLoopHandler.looper,
        &g_linkConflictLoopHandler, RemoveConflictInfoTimeliness, &conflictItem);
}

LinkConflictType GetConflictTypeWithErrcode(int32_t conflictErrcode)
{
    if (conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_P2P_GO_GC_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_PV1_BOTH_GO_ERR ||
        conflictErrcode == SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE ||
        conflictErrcode == SOFTBUS_CONN_PV2_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE) {
        return CONFLICT_ROLE;
    }
    if (conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_HML_NUM_LIMITED_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_P2P_NUM_LIMITED_CONFLICT) {
        return CONFLICT_LINK_NUM_LIMITED;
    }
    if (conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_55_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_225_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_255_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_525_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_555_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_HML_P2P_DFS_CHANNEL_CONFLICT) {
        return CONFLICT_THREE_VAP;
    }
    if (conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_P2P_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_HML_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_HML_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_P2P_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_P2P_HML_CHIP_CONFLICT) {
        return CONFLICT_SOFTAP;
    }
    return CONFLICT_BUTT;
}

static int32_t GenerateConflictInfo(const LinkConflictInfo *inputInfo, LinkConflictInfo *outputInfo)
{
    if (inputInfo == NULL || outputInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(&outputInfo->identifyInfo, sizeof(DevIdentifyInfo), &inputInfo->identifyInfo,
        sizeof(DevIdentifyInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy identifyInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    if (outputInfo->devIdCnt > 0) {
        SoftBusFree(outputInfo->devIdList);
        outputInfo->devIdList = NULL;
        outputInfo->devIdCnt = 0;
    }
    if (inputInfo->devIdCnt > 0) {
        char (*devIdList)[NETWORK_ID_BUF_LEN] =
            (char (*)[NETWORK_ID_BUF_LEN])SoftBusCalloc(inputInfo->devIdCnt * NETWORK_ID_BUF_LEN);
        if (devIdList == NULL) {
            LNN_LOGE(LNN_LANE, "calloc devIdList fail");
            return SOFTBUS_MALLOC_ERR;
        }
        outputInfo->devIdList = devIdList;
        if (memcpy_s(devIdList, inputInfo->devIdCnt * NETWORK_ID_BUF_LEN,
            inputInfo->devIdList, inputInfo->devIdCnt * NETWORK_ID_BUF_LEN) != EOK) {
            LNN_LOGE(LNN_LANE, "memcpy devIdList fail");
            SoftBusFree(devIdList);
            outputInfo->devIdList = NULL;
            return SOFTBUS_MEM_ERR;
        }
        outputInfo->devIdCnt = inputInfo->devIdCnt;
    }
    outputInfo->releaseLink = inputInfo->releaseLink;
    outputInfo->conflictType = inputInfo->conflictType;
    return SOFTBUS_OK;
}

static int32_t UpdateExistsLinkConflictInfo(const LinkConflictInfo *inputInfo)
{
    if (inputInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflictInfo lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LinkConflictInfo *item = NULL;
    LinkConflictInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_linkConflictList.list, LinkConflictInfo, node) {
        if (item->conflictType == inputInfo->conflictType &&
            memcmp(&item->identifyInfo, &inputInfo->identifyInfo, sizeof(DevIdentifyInfo)) == 0) {
            int32_t ret = GenerateConflictInfo(inputInfo, item);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_LANE, "generate conflictDevInfo fail");
                LinkConflictUnlock();
                return ret;
            }
            LinkConflictUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkConflictUnlock();
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t CreateNewLinkConflictInfo(const LinkConflictInfo *inputInfo)
{
    LinkConflictInfo *linkConflictItem = (LinkConflictInfo *)SoftBusCalloc(sizeof(LinkConflictInfo));
    if (linkConflictItem == NULL) {
        LNN_LOGE(LNN_LANE, "calloc linkConflictItem fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = GenerateConflictInfo(inputInfo, linkConflictItem);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate conflictDevInfo fail");
        SoftBusFree(linkConflictItem);
        return ret;
    }
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflict lock fail");
        SoftBusFree(linkConflictItem);
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_linkConflictList.list, &linkConflictItem->node);
    g_linkConflictList.cnt++;
    LinkConflictUnlock();
    char *anonyDevInfo = NULL;
    Anonymize(inputInfo->identifyInfo.type == IDENTIFY_TYPE_UDID_HASH ?
        inputInfo->identifyInfo.devInfo.udidHash : inputInfo->identifyInfo.devInfo.peerDevId, &anonyDevInfo);
    LNN_LOGI(LNN_LANE, "create new conflict link success, identifyType=%{public}d, devInfo=%{public}s, "
        "conflictType=%{public}d, releaseLink=%{public}d", inputInfo->identifyInfo.type, AnonymizeWrapper(anonyDevInfo),
        inputInfo->conflictType, inputInfo->releaseLink);
    AnonymizeFree(anonyDevInfo);
    return SOFTBUS_OK;
}

int32_t DelLinkConflictInfo(const DevIdentifyInfo *inputInfo, LinkConflictType conflictType)
{
    if (inputInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflict lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    char *anonyDevInfo = NULL;
    Anonymize(inputInfo->type == IDENTIFY_TYPE_UDID_HASH ?
        inputInfo->devInfo.udidHash : inputInfo->devInfo.peerDevId, &anonyDevInfo);
    LNN_LOGI(LNN_LANE, "start to del link conflict info by identifyType=%{public}d, devInfo=%{public}s,"
        " conflictType=%{public}d", inputInfo->type, AnonymizeWrapper(anonyDevInfo), conflictType);
    AnonymizeFree(anonyDevInfo);
    LinkConflictInfo *item = NULL;
    LinkConflictInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_linkConflictList.list, LinkConflictInfo, node) {
        if (item->conflictType == conflictType &&
            memcmp(&item->identifyInfo, inputInfo, sizeof(DevIdentifyInfo)) == 0) {
            ListDelete(&item->node);
            if (item->devIdCnt > 0) {
                SoftBusFree(item->devIdList);
                item->devIdList = NULL;
            }
            if (item->devIpCnt > 0) {
                SoftBusFree(item->devIpList);
                item->devIpList = NULL;
            }
            SoftBusFree(item);
            g_linkConflictList.cnt--;
            LinkConflictUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkConflictUnlock();
    LNN_LOGE(LNN_LANE, "not found link conflict info when del");
    return SOFTBUS_LANE_NOT_FOUND;
}

int32_t AddLinkConflictInfo(const LinkConflictInfo *inputInfo)
{
    if (inputInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = UpdateExistsLinkConflictInfo(inputInfo);
    if (ret == SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update link conflict info succ");
        RemoveConflictInfoTimelinessMsg(&inputInfo->identifyInfo, inputInfo->conflictType);
        ret = PostConflictInfoTimelinessMsg(&inputInfo->identifyInfo, inputInfo->conflictType);
        if (ret != SOFTBUS_OK) {
            (void)DelLinkConflictInfo(&inputInfo->identifyInfo, inputInfo->conflictType);
            LNN_LOGE(LNN_LANE, "post conflict info timeliness msg fail, reason=%{public}d", ret);
            return ret;
        }
        return SOFTBUS_OK;
    }
    ret = CreateNewLinkConflictInfo(inputInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create new link conflict info fail, reason=%{public}d", ret);
        return ret;
    }
    ret = PostConflictInfoTimelinessMsg(&inputInfo->identifyInfo, inputInfo->conflictType);
    if (ret != SOFTBUS_OK) {
        (void)DelLinkConflictInfo(&inputInfo->identifyInfo, inputInfo->conflictType);
        LNN_LOGE(LNN_LANE, "post conflict info timeliness msg fail, reason=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void GenerateConflictInfoWithDevIdHash(const DevIdentifyInfo *inputInfo, DevIdentifyInfo *outputInfo)
{
    char peerUdid[UDID_BUF_LEN] = {0};
    int32_t ret = LnnGetRemoteStrInfo(inputInfo->devInfo.peerDevId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error, ret=%{public}d", ret);
        return;
    }
    uint8_t udidHash[UDID_HASH_LEN] = {0};
    ret = SoftBusGenerateStrHash((const unsigned char*)peerUdid, strlen(peerUdid), udidHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate udidHash fail, ret=%{public}d", ret);
        return;
    }
    ret = ConvertBytesToHexString(outputInfo->devInfo.udidHash, CONFLICT_UDIDHASH_STR_LEN + 1, udidHash,
        CONFLICT_SHORT_HASH_LEN_TMP);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "convert bytes to string fail, ret=%{public}d", ret);
        return;
    }
}

int32_t FindLinkConflictInfoByDevId(const DevIdentifyInfo *inputInfo, LinkConflictType conflictType,
    LinkConflictInfo *outputInfo)
{
    if (inputInfo == NULL || outputInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    DevIdentifyInfo hashInfo;
    (void)memset_s(&hashInfo, sizeof(DevIdentifyInfo), 0, sizeof(DevIdentifyInfo));
    if (inputInfo->type == IDENTIFY_TYPE_DEV_ID) {
        hashInfo.type = IDENTIFY_TYPE_UDID_HASH;
        GenerateConflictInfoWithDevIdHash(inputInfo, &hashInfo);
    }
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflict lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LinkConflictInfo *item = NULL;
    LinkConflictInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_linkConflictList.list, LinkConflictInfo, node) {
        if (item->conflictType == conflictType &&
            (memcmp(&item->identifyInfo, inputInfo, sizeof(DevIdentifyInfo)) == 0 ||
            memcmp(&item->identifyInfo, &hashInfo, sizeof(DevIdentifyInfo)) == 0)) {
            int32_t ret = GenerateConflictInfo(item, outputInfo);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_LANE, "generate link conflict devInfo fail");
                LinkConflictUnlock();
                return ret;
            }
            LinkConflictUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkConflictUnlock();
    char *anonyDevInfo = NULL;
    Anonymize(inputInfo->type == IDENTIFY_TYPE_UDID_HASH ?
        inputInfo->devInfo.udidHash : inputInfo->devInfo.peerDevId, &anonyDevInfo);
    LNN_LOGE(LNN_LANE, "not found link conflict info by identifyType=%{public}d, devInfo=%{public}s,"
        " conflictType=%{public}d", inputInfo->type, AnonymizeWrapper(anonyDevInfo), conflictType);
    AnonymizeFree(anonyDevInfo);
    return SOFTBUS_LANE_NOT_FOUND;
}

int32_t CheckLinkConflictByReleaseLink(LaneLinkType releaseLink)
{
    if (releaseLink != LANE_HML) {
        LNN_LOGE(LNN_LANE, "invalid releaseLink=%{public}d", releaseLink);
        return SOFTBUS_INVALID_PARAM;
    }
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflict lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LinkConflictInfo *item = NULL;
    LinkConflictInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_linkConflictList.list, LinkConflictInfo, node) {
        if (item->releaseLink == releaseLink) {
            LinkConflictUnlock();
            LNN_LOGI(LNN_LANE, "link conflict info matched by releaseLink=%{public}d", releaseLink);
            return SOFTBUS_OK;
        }
    }
    LinkConflictUnlock();
    return SOFTBUS_LANE_NOT_FOUND;
}

static void HandleConflictInfoTimeliness(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg->obj");
        return;
    }
    LinkConflictInfo *conflictItem = (LinkConflictInfo*)msg->obj;
    LNN_LOGI(LNN_LANE, "handle conflict info timeliness");
    if (DelLinkConflictInfo(&conflictItem->identifyInfo, conflictItem->conflictType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "del link conflict info fail");
    }
    SoftBusFree(conflictItem);
}

static void MsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg");
        return;
    }
    switch (msg->what) {
        case MSG_TYPE_CONFLICT_TIMELINESS:
            HandleConflictInfoTimeliness(msg);
            break;
        default:
            LNN_LOGE(LNN_LANE, "msg type=%{public}d not support", msg->what);
            break;
    }
    return;
}

static int32_t InitLinkConflictLooper(void)
{
    g_linkConflictLoopHandler.name = (char *)"linkConflictLooper";
    g_linkConflictLoopHandler.HandleMessage = MsgHandler;
    g_linkConflictLoopHandler.looper = GetLooper(LOOP_TYPE_LNN);
    if (g_linkConflictLoopHandler.looper == NULL) {
        LNN_LOGE(LNN_LANE, "link conflict init looper fail");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

int32_t InitLaneLinkConflict(void)
{
    if (InitLinkConflictLooper() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init link conflict looper fail");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexInit(&g_linkConflictList.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "link conflict mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    ListInit(&g_linkConflictList.list);
    g_linkConflictList.cnt = 0;

    if (InitLinkWifiDirect() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init link wifidirect fail");
        (void)SoftBusMutexDestroy(&g_linkConflictList.lock);
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

void DeinitLaneLinkConflict(void)
{
    DeInitLinkWifiDirect();
    g_linkConflictLoopHandler.HandleMessage = NULL;
    g_linkConflictLoopHandler.looper = NULL;
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflictInfo lock fail");
        return;
    }
    LinkConflictInfo *item = NULL;
    LinkConflictInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_linkConflictList.list, LinkConflictInfo, node) {
        ListDelete(&item->node);
        if (item->devIdCnt > 0) {
            SoftBusFree(item->devIdList);
        }
        if (item->devIpCnt > 0) {
            SoftBusFree(item->devIpList);
        }
        SoftBusFree(item);
        g_linkConflictList.cnt--;
    }
    LinkConflictUnlock();
    (void)SoftBusMutexDestroy(&g_linkConflictList.lock);
}
