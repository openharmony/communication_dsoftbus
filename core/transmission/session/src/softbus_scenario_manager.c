/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "softbus_scenario_manager.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "common_list.h"
#include "kits/c/wifi_hid2d.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_bitmap.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"

#define MAC_STR_LEN   18
#define IFACE_LEN_MAX 32

#define VIDEO_BIT_POS  0
#define AUDIO_BIT_POS  1
#define FILE_BIT_POS   2

#define VALID_TYPE_MIN 3
#define VALID_TYPE_MAX 5

typedef struct ScenarioManager {
    // mac to iface name map
    SoftBusList* macIfacePairList;
    // mac to final map
    SoftBusList* scenarioItemList;
} ScenarioManager;

typedef struct MacIfacePair {
    ListNode node;
    char mac[MAC_STR_LEN];
    char iface[IFACE_LEN_MAX];
} MacIfacePair;

typedef struct ScenarioItem {
    ListNode node;
    char localMac[MAC_STR_LEN];
    char peerMac[MAC_STR_LEN];
    uint32_t finalType;
    int totalFileCount;
    int totalAudioCount;
    int totalVideoCount;
    ListNode businessCounterList;
} ScenarioItem;

typedef struct BusinessCounter {
    ListNode node;
    int localPid;
    int totalCount;
    int fileCount;
    int audioCount;
    int videoCount;
} BusinessCounter;

typedef struct OriginalScenario {
    char localMac[MAC_STR_LEN];
    char peerMac[MAC_STR_LEN];
    int localPid;
    int businessType;
} OriginalScenario;

typedef struct LocalScenarioCount {
    int allMacVideoCount;
    int allMacAudioCount;
    int allMacFileCount;
    int allMacTotalCount;
} LocalScenarioCount;

static ScenarioManager *g_manager = NULL;


static void NotifyWifi(const char *ifName, const char *localMac,
    const char *peerMac, uint32_t finalType, int32_t businessType)
{
    (void)peerMac;
    TRANS_LOGI(TRANS_CTRL, "ifName=%{public}s, finalType=%{public}u, businessType=%{public}d",
        ifName, finalType, businessType);
    Hid2dUpperScene *scene = NULL;
    scene = (Hid2dUpperScene *)SoftBusCalloc(sizeof(Hid2dUpperScene));
    if (scene == NULL) {
        TRANS_LOGE(TRANS_CTRL, "error, out of memory");
        return;
    }
    if (strcpy_s((char *)scene->mac, sizeof(scene->mac), localMac) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "set scene Mac err");
        SoftBusFree(scene);
        return;
    }
    scene->scene = finalType;
    if (businessType != SM_VIDEO_TYPE) {
        scene->fps = -1;
    }
    if (Hid2dSetUpperScene(ifName, scene) != 0) {
        TRANS_LOGE(TRANS_CTRL, "notify wifi err");
    } else {
        TRANS_LOGI(TRANS_CTRL, "notify wifi success");
    }
    SoftBusFree(scene);
}

static void OriginalScenarioInit(OriginalScenario *scenarioInfo,
    const char *localMac, const char *peerMac, int localPid, int businessType)
{
    if (localMac == NULL || peerMac == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Invalid parameter");
        return;
    }
    if (strcpy_s(scenarioInfo->localMac, sizeof(scenarioInfo->localMac), localMac) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "set scenarioInfo localMac err");
        return;
    }
    if (strcpy_s(scenarioInfo->peerMac, sizeof(scenarioInfo->peerMac), peerMac) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "set scenarioInfo peerMac err");
        return;
    }
    scenarioInfo->localPid = localPid;
    scenarioInfo->businessType = businessType;
}

static ScenarioItem *ScenarioManagerGetOrAddScenarioItem(ScenarioManager *manager,
    OriginalScenario *scenarioInfo, bool create)
{
    ScenarioItem *scenarioItem = NULL;
    ScenarioItem *tmp = NULL;
    LIST_FOR_EACH_ENTRY(tmp, &(manager->scenarioItemList->list), ScenarioItem, node) {
        if (strcmp(tmp->localMac, scenarioInfo->localMac) == 0 &&
            strcmp(tmp->peerMac, scenarioInfo->peerMac) == 0) {
            scenarioItem = tmp;
            break;
        }
    }
    if (scenarioItem == NULL) {
        if (!create) {
            TRANS_LOGI(TRANS_CTRL, "scenario item of this mac pair not exist!");
            return NULL;
        }
        TRANS_LOGI(TRANS_CTRL, "scenario item of this mac pair not exist, create it");
        scenarioItem = (ScenarioItem *)SoftBusCalloc(sizeof(ScenarioItem));
        if (scenarioItem == NULL) {
            return NULL;
        }
        if (strcpy_s(scenarioItem->localMac, sizeof(scenarioItem->localMac), scenarioInfo->localMac) != EOK) {
            SoftBusFree(scenarioItem);
            return NULL;
        }
        if (strcpy_s(scenarioItem->peerMac, sizeof(scenarioItem->peerMac), scenarioInfo->peerMac) != EOK) {
            SoftBusFree(scenarioItem);
            return NULL;
        }
        ListInit(&scenarioItem->businessCounterList);
        ListAdd(&(manager->scenarioItemList->list), &scenarioItem->node);
        manager->scenarioItemList->cnt++;
    }
    return scenarioItem;
}

static void ScenarioManagerDelScenarioItem(ScenarioManager *manager, ScenarioItem *scenarioItem)
{
    ScenarioItem *item = NULL;
    ScenarioItem *tmp = NULL;
    LIST_FOR_EACH_ENTRY(tmp, &(manager->scenarioItemList->list), ScenarioItem, node) {
        if (strcmp(tmp->localMac, scenarioItem->localMac) == 0 &&
            strcmp(tmp->peerMac, scenarioItem->peerMac) == 0) {
            item = tmp;
            break;
        }
    }
    if (item == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pair of the peer mac not found!");
        return;
    }
    if (IsListEmpty(&scenarioItem->businessCounterList)) {
        TRANS_LOGE(TRANS_CTRL, "remove empty list pair on put!");
        ListDelete(&scenarioItem->node);
        manager->scenarioItemList->cnt--;
        SoftBusFree(scenarioItem);
    }
}

static char *ScenarioManagerGetIfaceNameByMac(ScenarioManager *manager, const char *localMac)
{
    if (manager->macIfacePairList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "scenarioItemList hasn't initialized");
        return NULL;
    }
    MacIfacePair *pair = NULL;
    LIST_FOR_EACH_ENTRY(pair, &(manager->macIfacePairList->list), MacIfacePair, node) {
        if (strcmp(localMac, pair->mac) == 0) {
            return pair->iface;
        }
    }
    return NULL;
}

static bool ScenarioManagerAddIfaceNameByLocalMac(ScenarioManager *manager,
    const char *localMac, const char *ifaceName)
{
    if (manager->macIfacePairList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "scenarioItemList hasn't initialized");
        return false;
    }
    MacIfacePair *pair = (MacIfacePair *)SoftBusCalloc(sizeof(MacIfacePair));
    if (pair == NULL) {
        TRANS_LOGE(TRANS_CTRL, "error, out of memory");
        return false;
    }
    if (strcpy_s(pair->mac, sizeof(pair->mac), localMac) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy MacIfacePair localMac err");
        SoftBusFree(pair);
        return false;
    }
    if (strcpy_s(pair->iface, sizeof(pair->iface), ifaceName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "set MacIfacePair ifaceName err");
        SoftBusFree(pair);
        return false;
    }
    ListAdd(&manager->macIfacePairList->list, &pair->node);
    manager->macIfacePairList->cnt++;
    return true;
}

static char *ScenarioManagerFindIfaceNameByLocalMac(const char *localMac)
{
    // it's fake, gona replaced by wifi interface
    static char *LOCAL_MAC_1 = "18:65";
    static char *LOCAL_MAC_2 = "82:13";
    if (strcmp(localMac, LOCAL_MAC_1) == 0) {
        return "en0";
    } else if (strcmp(localMac, LOCAL_MAC_2) == 0) {
        return "en1";
    }
    return NULL;
}

static bool ScenarioManagerCheckAndUpdateIfaceName(ScenarioManager *manager, const char *localMac)
{
    if (manager == NULL || manager->macIfacePairList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "scenarioItemList hasn't initialized");
        return false;
    }
    if (SoftBusMutexLock(&(manager->macIfacePairList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed!");
        return false;
    }
    const char *ifaceName = ScenarioManagerGetIfaceNameByMac(manager, localMac);
    if (ifaceName != NULL) {
        (void)SoftBusMutexUnlock(&(manager->macIfacePairList->lock));
        return true;
    }
    ifaceName = ScenarioManagerFindIfaceNameByLocalMac(localMac);
    if (ifaceName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "inteface name not found!");
        (void)SoftBusMutexUnlock(&(manager->macIfacePairList->lock));
        return false;
    }
    bool result = ScenarioManagerAddIfaceNameByLocalMac(manager, localMac, ifaceName);
    (void)SoftBusMutexUnlock(&(manager->macIfacePairList->lock));
    return result;
}

static void ScenarioManagerAddBusinessType(ScenarioManager *manager,
    ScenarioItem *scenarioItem, BusinessCounter *counter, int businessType)
{
    switch (businessType) {
        case SM_FILE_TYPE:
            counter->fileCount++;
            counter->totalCount++;
            scenarioItem->totalFileCount++;
            break;
        case SM_AUDIO_TYPE:
            counter->audioCount++;
            counter->totalCount++;
            scenarioItem->totalAudioCount++;
            break;
        case SM_VIDEO_TYPE:
            counter->videoCount++;
            counter->totalCount++;
            scenarioItem->totalVideoCount++;
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "business type not supported!");
            return;
    }
    TRANS_LOGI(TRANS_CTRL,
        "same mac pair: businessType=%{public}d, totalFileCount=%{public}d, totalAudioCount=%{public}d, "
        "totalVideoCount=%{public}d",
        businessType, scenarioItem->totalFileCount, scenarioItem->totalAudioCount,
        scenarioItem->totalVideoCount);
}

static void ScenarioManagerDelBusinessType(ScenarioManager *manager,
    ScenarioItem *scenarioItem, BusinessCounter *counter, int businessType)
{
    int *singleCount = NULL;
    int *itemCount = NULL;
    switch (businessType) {
        case SM_FILE_TYPE:
            singleCount = &counter->fileCount;
            itemCount = &scenarioItem->totalFileCount;
            break;
        case SM_AUDIO_TYPE:
            singleCount = &counter->audioCount;
            itemCount = &scenarioItem->totalAudioCount;
            break;
        case SM_VIDEO_TYPE:
            singleCount = &counter->videoCount;
            itemCount = &scenarioItem->totalVideoCount;
            break;
        default:
            break;
    }
    if (singleCount == NULL || itemCount == NULL) {
        TRANS_LOGE(TRANS_CTRL, "business type not supported!");
        return;
    }
    if (*singleCount <= 0 || counter->totalCount <= 0 || *itemCount <= 0) {
        TRANS_LOGE(TRANS_CTRL, "error, count of the type wrong!");
        return;
    }
    (void)(*singleCount)--;
    counter->totalCount--;
    (void)(*itemCount)--;
    TRANS_LOGI(TRANS_CTRL,
        "businessType=%{public}d, filecount=%{public}d, audiocuont=%{public}d, videocount=%{public}d",
        businessType, scenarioItem->totalFileCount, scenarioItem->totalAudioCount,
        scenarioItem->totalVideoCount);
}

static int32_t ScenarioManagerGetBitPosByBusinessType(int businessType)
{
    int32_t bitPos = 0;
    switch (businessType) {
        case SM_FILE_TYPE:
            bitPos = FILE_BIT_POS;
            break;
        case SM_AUDIO_TYPE:
            bitPos = AUDIO_BIT_POS;
            break;
        case SM_VIDEO_TYPE:
            bitPos = VIDEO_BIT_POS;
            break;
        default:
            TRANS_LOGI(TRANS_CTRL, "business type not supported!");
            return -1;
    }
    return bitPos;
}

static bool ScenarioManagerIsBusinesExisted(ScenarioManager *manager,
    ScenarioItem *item, int businessType)
{
    TRANS_LOGI(TRANS_CTRL,
        "businessType=%{public}d, filecount=%{public}d, audiocuont=%{public}d, videocount=%{public}d",
        businessType, item->totalFileCount, item->totalAudioCount, item->totalVideoCount);
    switch (businessType) {
        case SM_FILE_TYPE:
            return item->totalFileCount > 0;
        case SM_AUDIO_TYPE:
            return item->totalAudioCount > 0;
        case SM_VIDEO_TYPE:
            return item->totalVideoCount > 0;
        default:
            return false;
    }
}

static LocalScenarioCount *GetScenarioCount(ScenarioManager *manager)
{
    LocalScenarioCount *localScenarioCount = NULL;
    ScenarioItem *tmp = NULL;
    localScenarioCount = (LocalScenarioCount *)SoftBusCalloc(sizeof(LocalScenarioCount));
    if (localScenarioCount == NULL) {
        TRANS_LOGE(TRANS_CTRL, "error, out of memory");
        return NULL;
    }
    LIST_FOR_EACH_ENTRY(tmp, &(manager->scenarioItemList->list), ScenarioItem, node) {
        localScenarioCount->allMacVideoCount += tmp->totalVideoCount;
        localScenarioCount->allMacAudioCount += tmp->totalAudioCount;
        localScenarioCount->allMacFileCount += tmp->totalFileCount;
    }
    localScenarioCount->allMacTotalCount =
        localScenarioCount->allMacVideoCount + localScenarioCount->allMacAudioCount
            + localScenarioCount->allMacFileCount;
    return localScenarioCount;
}

static void ScenarioManagerDoNotifyIfNeed(ScenarioManager *manager,
    OriginalScenario *info, bool isAdd)
{
    bool notify = false;
    ScenarioItem *item = ScenarioManagerGetOrAddScenarioItem(manager, info, false);
    if (item == NULL) {
        TRANS_LOGE(TRANS_CTRL, "scenario item not found!");
        return;
    }
    LocalScenarioCount *localScenarioCount = GetScenarioCount(manager);
    if (localScenarioCount == NULL) {
        TRANS_LOGE(TRANS_CTRL, "localScenarioCount is null!");
        return;
    }
    uint32_t finalType = item->finalType;
    int bitPos = ScenarioManagerGetBitPosByBusinessType(info->businessType);
    if (bitPos < 0) {
        TRANS_LOGE(TRANS_CTRL, "error, invalid business type!");
        SoftBusFree(localScenarioCount);
        return;
    }
    if (isAdd) {
        TRANS_LOGI(TRANS_CTRL, "finalType=%{public}d, bitPos=%{public}d", finalType, bitPos);
        if (!SoftbusIsBitmapSet(&finalType, bitPos)) {
            SoftbusBitmapSet(&finalType, bitPos);
            item->finalType = finalType;
            TRANS_LOGI(TRANS_CTRL, "finalType=%{public}d, bitPos=%{public}d", finalType, bitPos);
        }
        if (localScenarioCount->allMacTotalCount == 0) {
            notify = true;
        }
    } else {
        TRANS_LOGI(TRANS_CTRL, "finalType=%{public}d, bitPos=%{public}d", finalType, bitPos);
        if (SoftbusIsBitmapSet(&finalType, bitPos) &&
            !ScenarioManagerIsBusinesExisted(manager, item, info->businessType)) {
            SoftbusBitmapClr(&finalType, bitPos);
            item->finalType = finalType;
            TRANS_LOGI(TRANS_CTRL, "finalType=%{public}d, bitPos=%{public}d", finalType, bitPos);
        }
        if (localScenarioCount->allMacTotalCount == 0) {
            notify = true;
        }
    }
    if (notify) {
        TRANS_LOGI(TRANS_CTRL,
            "current businessType of finalType=%{public}d", item->finalType);
        const char* ifaceName = "chba";
        // do notify here
        NotifyWifi(ifaceName, item->localMac, item->peerMac, item->finalType, info->businessType);
    }
    SoftBusFree(localScenarioCount);
}

static void ShowLocalScenarioCountMessage(const LocalScenarioCount *localScenarioCount)
{
    TRANS_LOGI(TRANS_CTRL,
        "allMacTotalCount=%{public}d, allMacVideoCount=%{public}d, "
        "allMacAudioCount=%{public}d, allMacFileCount=%{public}d",
        localScenarioCount->allMacTotalCount, localScenarioCount->allMacVideoCount,
        localScenarioCount->allMacAudioCount, localScenarioCount->allMacFileCount);
}

static int32_t AddOriginalScenario(ScenarioManager *manager, OriginalScenario *info)
{
    if (SoftBusMutexLock(&(manager->scenarioItemList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed!");
        return SOFTBUS_LOCK_ERR;
    }
    ScenarioItem *scenarioItem = ScenarioManagerGetOrAddScenarioItem(manager, info, true);
    if (scenarioItem == NULL) {
        TRANS_LOGE(TRANS_CTRL, "error, get scenario item failed");
        (void)SoftBusMutexUnlock(&(manager->scenarioItemList->lock));
        return SOFTBUS_NOT_FIND;
    }
    BusinessCounter *counter = NULL;
    BusinessCounter *tmp = NULL;
    LIST_FOR_EACH_ENTRY(tmp, &scenarioItem->businessCounterList,  BusinessCounter, node) {
        if (tmp->localPid == info->localPid) {
            counter = tmp;
            break;
        }
    }
    if (counter == NULL) {
        counter = (BusinessCounter *)SoftBusCalloc(sizeof(BusinessCounter));
        if (counter == NULL) {
            TRANS_LOGE(TRANS_CTRL, "error, out of memory");
            (void)SoftBusMutexUnlock(&(manager->scenarioItemList->lock));
            return SOFTBUS_MALLOC_ERR;
        }
        counter->localPid = info->localPid;
        ListAdd(&scenarioItem->businessCounterList, &counter->node);
        TRANS_LOGI(TRANS_CTRL, "add localPid = %{public}d", counter->localPid);
    } else {
        TRANS_LOGI(TRANS_CTRL, "businessCounter already exist");
    }
    ScenarioManagerDoNotifyIfNeed(manager, info, true);
    ScenarioManagerAddBusinessType(manager, scenarioItem, counter, info->businessType);
    LocalScenarioCount *localScenarioCount = GetScenarioCount(manager);
    if (localScenarioCount == NULL) {
        TRANS_LOGE(TRANS_CTRL, "failed to apply for memory");
        (void)SoftBusMutexUnlock(&(manager->scenarioItemList->lock));
        return SOFTBUS_MALLOC_ERR;
    }
    ShowLocalScenarioCountMessage(localScenarioCount);
    SoftBusFree(localScenarioCount);
    (void)SoftBusMutexUnlock(&(manager->scenarioItemList->lock));
    return SOFTBUS_OK;
}

static int32_t DelOriginalScenario(ScenarioManager *manager, OriginalScenario *info)
{
    if (SoftBusMutexLock(&(manager->scenarioItemList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed!");
        return SOFTBUS_LOCK_ERR;
    }
    ScenarioItem *scenarioItem = ScenarioManagerGetOrAddScenarioItem(manager, info, false);
    if (scenarioItem == NULL) {
        TRANS_LOGE(TRANS_CTRL, "error, get scenario item failed");
        (void)SoftBusMutexUnlock(&(manager->scenarioItemList->lock));
        return SOFTBUS_NOT_FIND;
    }
    BusinessCounter *counter = NULL;
    BusinessCounter *tmp = NULL;
    LIST_FOR_EACH_ENTRY(tmp, &scenarioItem->businessCounterList,  BusinessCounter, node) {
        if (tmp->localPid == info->localPid) {
            counter = tmp;
            break;
        }
    }
    if (counter == NULL) {
        TRANS_LOGE(TRANS_CTRL, "error, counter of the pid not found!");
        (void)SoftBusMutexUnlock(&(manager->scenarioItemList->lock));
        return SOFTBUS_NOT_FIND;
    }
    ScenarioManagerDelBusinessType(manager, scenarioItem, counter, info->businessType);
    if (counter->totalCount <= 0) {
        TRANS_LOGE(TRANS_CTRL, "error, delete a counter form list!");
        ListDelete(&counter->node);
        TRANS_LOGI(TRANS_CTRL, "delete localPid = %{public}d", counter->localPid);
        SoftBusFree(counter);
    }
    ScenarioManagerDoNotifyIfNeed(manager, info, false);
    ScenarioManagerDelScenarioItem(manager, scenarioItem);
    LocalScenarioCount *localScenarioCount = GetScenarioCount(manager);
    if (localScenarioCount == NULL) {
        TRANS_LOGE(TRANS_CTRL, "failed to apply for memory");
        (void)SoftBusMutexUnlock(&(manager->scenarioItemList->lock));
        return SOFTBUS_MALLOC_ERR;
    }
    ShowLocalScenarioCountMessage(localScenarioCount);
    SoftBusFree(localScenarioCount);
    (void)SoftBusMutexUnlock(&(manager->scenarioItemList->lock));
    return SOFTBUS_OK;
}

static int32_t UpdateOriginalScenario(ScenarioManager *manager, OriginalScenario *info, bool isAdd)
{
    if (strlen(info->localMac) == 0 || strlen(info->peerMac) == 0 || info->localPid < 0) {
        TRANS_LOGE(TRANS_CTRL, "invalid parameters!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->businessType < VALID_TYPE_MIN || info->businessType > VALID_TYPE_MAX) {
        TRANS_LOGE(TRANS_CTRL, "type not supportted!");
        return SOFTBUS_INVALID_NUM;
    }
    if (!ScenarioManagerCheckAndUpdateIfaceName(manager, info->localMac)) {
        TRANS_LOGE(TRANS_CTRL, "invalid local mac!");
        return SOFTBUS_INVALID_NUM;
    }
    TRANS_LOGI(TRANS_CTRL, "UpdateOriginalScenario: "
        "localPid=%{public}d, businessType=%{public}d, isAdd=%{public}d",
        info->localPid, info->businessType, isAdd);

    if (manager == NULL || manager->scenarioItemList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "scenarioItemList hasn't initialized");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = isAdd ? AddOriginalScenario(manager, info) : DelOriginalScenario(manager, info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "update scenario info failed: ret=%{public}d", ret);
        return ret;
    }
    return ret;
}

static void ScenarioManagerClearMacIfacePairList(ScenarioManager *manager)
{
    if (manager->scenarioItemList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "before clean : macIfacePairList numer=%{public}d", manager->macIfacePairList->cnt);
    MacIfacePair *pair = NULL;
    MacIfacePair *nextPair = NULL;
    if (SoftBusMutexLock(&(manager->macIfacePairList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pair, nextPair, &manager->macIfacePairList->list,  MacIfacePair, node) {
        ListDelete(&pair->node);
        SoftBusFree(pair);
        manager->macIfacePairList->cnt--;
    }
    TRANS_LOGI(TRANS_CTRL, "before clean : macIfacePairList numer=%{public}d", manager->macIfacePairList->cnt);
    (void)SoftBusMutexUnlock(&(manager->macIfacePairList->lock));
}

static void ScenarioManagerClearBusinessCounterList(ListNode *list)
{
    BusinessCounter *counter = NULL;
    BusinessCounter *tmp = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(counter, tmp, list, BusinessCounter, node) {
        ListDelete(&counter->node);
        SoftBusFree(counter);
    }
}

static void ScenarioManagerClearScenarioItemList(ScenarioManager *manager)
{
    if (manager->scenarioItemList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "before clean:scenarioItemList numer=%{public}d", manager->scenarioItemList->cnt);
    ScenarioItem *item = NULL;
    ScenarioItem *tmp = NULL;
    if (SoftBusMutexLock(&(manager->scenarioItemList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, tmp, &manager->scenarioItemList->list,  ScenarioItem, node) {
        ScenarioManagerClearBusinessCounterList(&item->businessCounterList);
        ListDelete(&item->node);
        SoftBusFree(item);
        manager->scenarioItemList->cnt--;
    }
    TRANS_LOGI(TRANS_CTRL, "after clean:scenarioItemList numer=%{public}d", manager->scenarioItemList->cnt);
    (void)SoftBusMutexUnlock(&(manager->scenarioItemList->lock));
}

static int32_t ScenarioManagerAddScenario(ScenarioManager *manager, const char *localMac,
    const char *peerMac, int localPid, int businessType)
{
    OriginalScenario scenarioInfo;
    OriginalScenarioInit(&scenarioInfo, localMac, peerMac, localPid, businessType);
    int32_t ret = UpdateOriginalScenario(manager, &scenarioInfo, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "add scenario info failed!");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t ScenarioManagerDelScenario(ScenarioManager *manager, const char *localMac,
    const char *peerMac, int localPid, int businessType)
{
    OriginalScenario scenarioInfo;
    OriginalScenarioInit(&scenarioInfo, localMac, peerMac, localPid, businessType);
    int32_t ret = UpdateOriginalScenario(manager, &scenarioInfo, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "delete scenario info failed!");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t AddScenario(const char *localMac, const char *peerMac, int localPid, int businessType)
{
    return ScenarioManagerAddScenario(g_manager, localMac, peerMac, localPid, businessType);
}

int32_t DelScenario(const char *localMac, const char *peerMac, int localPid, int businessType)
{
    return ScenarioManagerDelScenario(g_manager, localMac, peerMac, localPid, businessType);
}


int32_t ScenarioManagerGetInstance()
{
    static ScenarioManager manager;
    if (g_manager == NULL) {
        manager.macIfacePairList = CreateSoftBusList();
        manager.scenarioItemList = CreateSoftBusList();
        g_manager = &manager;
    }
    TRANS_LOGI(TRANS_CTRL, "creat g_manager success!");
    return SOFTBUS_OK;
}

void ScenarioManagerdestroyInstance()
{
    if (g_manager == NULL) {
        TRANS_LOGE(TRANS_CTRL, "manager is null!");
        return;
    }
    ScenarioManagerClearMacIfacePairList(g_manager);
    ScenarioManagerClearScenarioItemList(g_manager);
    DestroySoftBusList(g_manager->macIfacePairList);
    g_manager->macIfacePairList = NULL;
    DestroySoftBusList(g_manager->scenarioItemList);
    g_manager->scenarioItemList = NULL;
    g_manager = NULL;
}
