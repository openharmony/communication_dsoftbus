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
#include "p2plink_reference.h"

#include <string.h>

#include "p2plink_common.h"
#include "p2plink_control_message.h"
#include "p2plink_device.h"
#include "p2plink_loop.h"

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

typedef struct {
    ListNode node;
    char mac[P2P_MAC_LEN];
    int32_t refCnt;
} RefMacItem;

typedef struct {
    ListNode node;
    int32_t pid;
    int32_t refCnt;
    ListNode macList;
} RefPidItem;

static ListNode g_pidList = {0};
static int32_t g_myP2pRef = 0;

static RefPidItem *FindPidItem(int32_t pid)
{
    RefPidItem *item = NULL;
    RefPidItem *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_pidList, RefPidItem, node) {
        if (item->pid == pid) {
            return item;
        }
    }
    return NULL;
}

static RefMacItem *FindMacItem(const ListNode *macList, const char *peerMac)
{
    RefMacItem *item = NULL;
    RefMacItem *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, macList, RefMacItem, node) {
        if (strcmp(item->mac, peerMac) == 0) {
            return item;
        }
    }
    return NULL;
}

void AddNewMacItem(ListNode *macList, const char *mac)
{
    RefMacItem *mItem = (RefMacItem *)SoftBusMalloc(sizeof(RefMacItem));
    if (mItem == NULL) {
        return;
    }
    int32_t ret = strcpy_s(mItem->mac, sizeof(mItem->mac), mac);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy failed.");
        SoftBusFree(mItem);
        return;
    }
    mItem->refCnt = 1;
    ListAdd(macList, &mItem->node);
}

void AddNewPidItem(int32_t pid, const char* mac)
{
    RefPidItem *pItem = (RefPidItem *)SoftBusMalloc(sizeof(RefPidItem));
    if (pItem == NULL) {
        return;
    }
    ListInit(&pItem->macList);
    pItem->pid = pid;
    ListAdd(&g_pidList, &pItem->node);
    AddNewMacItem(&pItem->macList, mac);
}

void P2pLinkAddPidMacRef(int32_t pid, const char *mac)
{
    RefPidItem *pItem = NULL;
    RefMacItem *mItem = NULL;

    pItem = FindPidItem(pid);
    if (pItem == NULL) {
        AddNewPidItem(pid, mac);
        return;
    }
    mItem = FindMacItem(&pItem->macList, mac);
    if (mItem == NULL) {
        AddNewMacItem(&pItem->macList, mac);
    } else {
        mItem->refCnt++;
        pItem->refCnt++;
    }
}

void P2pLinkDelPidRef(int32_t pid)
{
    RefPidItem *pItem = NULL;
    RefMacItem *mItem = NULL;
    RefMacItem *next = NULL;

    pItem = FindPidItem(pid);
    if (pItem == NULL) {
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(mItem, next, &pItem->macList, RefMacItem, node) {
        ListDelete(&mItem->node);
        pItem->refCnt -= mItem->refCnt;
        SoftBusFree(mItem);
    }
    ListDelete(&pItem->node);
    SoftBusFree(pItem);
}

void P2pLinkDelPidMacRef(int32_t pid, const char *mac)
{
    RefPidItem *pItem = NULL;
    RefMacItem *mItem = NULL;

    pItem = FindPidItem(pid);
    if (pItem == NULL) {
        return;
    }
    mItem = FindMacItem(&(pItem->macList), mac);
    if (mItem == NULL) {
        return;
    }
    mItem->refCnt--;
    pItem->refCnt--;
    if (mItem->refCnt > 0) {
        return;
    }
    ListDelete(&mItem->node);
    SoftBusFree(mItem);
    if (IsListEmpty(&pItem->macList)) {
        ListDelete(&pItem->node);
        SoftBusFree(pItem);
    }
}

int32_t P2pLinGetMacRefCnt(int32_t pid, const char *mac)
{
    RefPidItem *pItem = NULL;
    RefMacItem *mItem = NULL;

    pItem = FindPidItem(pid);
    if (pItem == NULL) {
        return 0;
    }
    mItem = FindMacItem(&(pItem->macList), mac);
    if (mItem == NULL) {
        return 0;
    }
    return mItem->refCnt;
}

void P2pLinkDelMyP2pRef(void)
{
    if (g_myP2pRef == 0) {
        return;
    }

    if (g_myP2pRef > 0) {
        g_myP2pRef--;
    }

    if (g_myP2pRef == 0) {
        P2pLinkDevEnterDiscState();
    }
}

void P2pLinkAddMyP2pRef(void)
{
    g_myP2pRef++;
}

int32_t P2pLinkGetMyP2pRef(void)
{
    return g_myP2pRef;
}

void DisConnectByPid(int32_t pid)
{
    RefPidItem *pItem = NULL;
    RefMacItem *mItem = NULL;
    RefMacItem *next = NULL;
    ConnectedNode *connedItem = NULL;
    int32_t i;

    pItem = FindPidItem(pid);
    if (pItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "no find pid %d.", pid);
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(mItem, next, &pItem->macList, RefMacItem, node) {
        connedItem = P2pLinkGetConnedDevByMac(mItem->mac);
        if ((connedItem == NULL) || strlen(connedItem->peerIp) == 0) {
            continue;
        }
        for (i = 0; i < mItem->refCnt; i++) {
            int32_t ret = P2pLinkSendDisConnect(&connedItem->chanId, P2pLinkGetMyMac());
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "disconnect failed.");
            }
            ret = P2pLinkSharelinkRemoveGroup();
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "remove failed.");
            }
            P2pLinkDelMyP2pRef();
        }
    }
    P2pLinkDelPidRef(pid);
}

void P2pLinkDumpRef(void)
{
    RefPidItem *pItem = NULL;
    RefPidItem *pNext = NULL;
    RefMacItem *mItem = NULL;
    RefMacItem *mNext = NULL;

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "total ref cnt %d.", g_myP2pRef);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "my ref cnt:");
    LIST_FOR_EACH_ENTRY_SAFE(pItem, pNext, &g_pidList, RefPidItem, node) {
        LIST_FOR_EACH_ENTRY_SAFE(mItem, mNext, &pItem->macList, RefMacItem, node) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "pid %d peer ref %d", pItem->pid, mItem->refCnt);
        }
    }
}

void P2pLinkInitRef(void)
{
    g_myP2pRef = 0;
    ListInit(&g_pidList);
}

void P2pLinkRefClean(void)
{
    RefPidItem *item = NULL;
    RefPidItem *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_pidList, RefPidItem, node) {
        P2pLinkDelPidRef(item->pid);
    }
    g_myP2pRef = 0;
}

void P2pLinkMyP2pRefClean(void)
{
    int32_t i;
    int32_t refCnt = P2pLinkGetMyP2pRef();

    for (i = 0; i < refCnt; i++) {
        int32_t ret = P2pLinkSharelinkRemoveGroup();
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "remove failed.");
        } else {
            P2pLinkDelMyP2pRef();
        }
    }
}