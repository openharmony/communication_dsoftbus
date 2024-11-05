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

#include "message_handler.h"

#include <securec.h>
#include <atomic>
#include "ffrt.h"
#include "c/ffrt_ipc.h"

#include "common_list.h"
#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define LOOP_NAME_LEN 16
#define TIME_THOUSANDS_MULTIPLIER 1000LL
#define MAX_LOOPER_CNT 30U
#define MAX_LOOPER_PRINT_CNT 64

static std::atomic<uint32_t> g_looperCnt(0);

struct FfrtMsgQueue {
    ffrt::queue *msgQueue;
};

typedef struct {
    SoftBusMessage *msg;
    ListNode node;
    ffrt::task_handle *msgHandle;
} SoftBusMessageNode;

struct SoftBusLooperContext {
    ListNode msgHead;
    char name[LOOP_NAME_LEN];
    SoftBusMessage *currentMsg;
    unsigned int msgSize;
    ffrt::mutex *mtx;
    volatile bool stop; // destroys looper, stop = true
};

static int64_t UptimeMicros(void)
{
    SoftBusSysTime t = {
        .sec = 0,
        .usec = 0,
    };
    SoftBusGetTime(&t);
    int64_t when = t.sec * TIME_THOUSANDS_MULTIPLIER * TIME_THOUSANDS_MULTIPLIER + t.usec;
    return when;
}

NO_SANITIZE("cfi") static void FreeSoftBusMsg(SoftBusMessage *msg)
{
    if (msg->FreeMessage == nullptr) {
        SoftBusFree(msg);
    } else {
        msg->FreeMessage(msg);
    }
}

SoftBusMessage *MallocMessage(void)
{
    SoftBusMessage *msg = static_cast<SoftBusMessage *>(SoftBusCalloc(sizeof(SoftBusMessage)));
    if (msg == nullptr) {
        COMM_LOGE(COMM_UTILS, "malloc SoftBusMessage failed");
        return nullptr;
    }
    return msg;
}

void FreeMessage(SoftBusMessage *msg)
{
    if (msg != nullptr) {
        FreeSoftBusMsg(msg);
        msg = nullptr;
    }
}

static void DumpLooperLocked(const SoftBusLooperContext *context)
{
    int32_t i = 0;
    ListNode *item = nullptr;
    LIST_FOR_EACH(item, &context->msgHead) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        SoftBusMessage *msg = itemNode->msg;
        if (i > MAX_LOOPER_PRINT_CNT) {
            COMM_LOGW(COMM_UTILS, "many messages left unprocessed, msgSize=%{public}u",
                context->msgSize);
            break;
        }
        COMM_LOGD(COMM_UTILS,
            "DumpLooper. i=%{public}d, handler=%{public}s, what=%{public}" PRId32 ", arg1=%{public}" PRIu64 ", "
            "arg2=%{public}" PRIu64 ", time=%{public}" PRId64 "",
            i, msg->handler->name, msg->what, msg->arg1, msg->arg2, msg->time);
        i++;
    }
}

void DumpLooper(const SoftBusLooper *looper)
{
    if (looper == nullptr) {
        return;
    }
    SoftBusLooperContext *context = looper->context;
    context->mtx->lock();
    if (looper->dumpable) {
        DumpLooperLocked(context);
    }
    context->mtx->unlock();
}

struct LoopConfigItem {
    int type;
    SoftBusLooper *looper;
};

static struct LoopConfigItem g_loopConfig[] = {
    {LOOP_TYPE_DEFAULT, nullptr},
    {LOOP_TYPE_CONN, nullptr},
    {LOOP_TYPE_LNN, nullptr},
};

static void ReleaseLooper(const SoftBusLooper *looper)
{
    const uint32_t len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (uint32_t i = 0; i < len; i++) {
        if (g_loopConfig[i].looper == looper) {
            g_loopConfig[i].looper = nullptr;
            return;
        }
    }
}

static void DumpMsgInfo(const SoftBusMessage *msg)
{
    if (msg->handler == nullptr) {
        return;
    }
    COMM_LOGD(COMM_UTILS, "DumpMsgInfo.handler=%{public}s, what=%{public}" PRId32 ", arg1=%{public}" PRIu64 ", "
        "arg2=%{public}" PRIu64 ", time=%{public}" PRId64 "",
        msg->handler->name, msg->what, msg->arg1, msg->arg2, msg->time);
}

static int32_t GetMsgNodeFromContext(SoftBusMessageNode **msgNode,
    const SoftBusMessage *tmpMsg, const SoftBusLooper *looper)
{
    looper->context->mtx->lock();
    if (looper->context->stop) {
        COMM_LOGE(COMM_UTILS, "cancel handle with looper is stop, name=%{public}s", looper->context->name);
        looper->context->mtx->unlock();
        return SOFTBUS_LOOPER_ERR;
    }
    ListNode *item = nullptr;
    ListNode *nextItem = nullptr;
    LIST_FOR_EACH_SAFE(item, nextItem, &(looper->context->msgHead)) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        SoftBusMessage *msg = itemNode->msg;
        if (tmpMsg->what == msg->what && tmpMsg->arg1 == msg->arg1 && tmpMsg->arg2 == msg->arg2 &&
            tmpMsg->time == msg->time && tmpMsg->handler == msg->handler) {
            ListDelete(&itemNode->node);
            *msgNode = itemNode;
            looper->context->msgSize--;
            looper->context->mtx->unlock();
            return SOFTBUS_OK;
        }
    }
    COMM_LOGE(COMM_UTILS, "no get correct msg from context, time=%{public}" PRId64"", tmpMsg->time);
    looper->context->mtx->unlock();
    return SOFTBUS_LOOPER_ERR;
}

static int32_t SubmitMsgToFfrt(SoftBusMessageNode *msgNode, const SoftBusLooper *looper, uint64_t delayMicros)
{
    msgNode->msgHandle = new (std::nothrow)ffrt::task_handle();
    if (msgNode->msgHandle == nullptr) {
        COMM_LOGE(COMM_UTILS, "ffrt msgHandle SoftBusCalloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    SoftBusMessage tmpMsg = {
        .what = msgNode->msg->what,
        .arg1 = msgNode->msg->arg1,
        .arg2 = msgNode->msg->arg2,
        .time = msgNode->msg->time,
        .handler = msgNode->msg->handler,
    };
    *(msgNode->msgHandle) = looper->queue->msgQueue->submit_h([tmpMsg, looper] {
        ffrt_this_task_set_legacy_mode(true);
        if (looper == nullptr || looper->context == nullptr) {
            COMM_LOGE(COMM_UTILS, "invalid looper para when handle");
            return;
        }
        SoftBusMessageNode *currentMsgNode = nullptr;
        if (GetMsgNodeFromContext(&currentMsgNode, &tmpMsg, looper) != SOFTBUS_OK) {
            COMM_LOGE(COMM_UTILS, "get currentMsgNode from context fail");
            return;
        }
        SoftBusMessage *currentMsg = currentMsgNode->msg;
        if (currentMsg->handler != nullptr && currentMsg->handler->HandleMessage != nullptr) {
            DumpMsgInfo(currentMsg);
            currentMsg->handler->HandleMessage(currentMsg);
        } else {
            COMM_LOGE(COMM_UTILS, "handler is null when handle msg, name=%{public}s", looper->context->name);
        }
        FreeSoftBusMsg(currentMsg);
        delete (currentMsgNode->msgHandle);
        SoftBusFree(currentMsgNode);
    }, ffrt::task_attr().delay(delayMicros));
    return SOFTBUS_OK;
}

static void InsertMsgWithTime(SoftBusLooperContext *context, SoftBusMessageNode *msgNode)
{
    ListNode *item = nullptr;
    ListNode *nextItem = nullptr;
    bool insert = false;
    LIST_FOR_EACH_SAFE(item, nextItem, &context->msgHead) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        if (itemNode->msg->time > msgNode->msg->time) {
            ListTailInsert(item, &(msgNode->node));
            insert = true;
            break;
        }
    }
    if (!insert) {
        ListTailInsert(&(context->msgHead), &(msgNode->node));
    }
}

static void PostMessageWithFfrt(const SoftBusLooper *looper, SoftBusMessage *msg, uint64_t delayMicros)
{
    SoftBusMessageNode *msgNode = static_cast<SoftBusMessageNode *>(SoftBusCalloc(sizeof(SoftBusMessageNode)));
    if (msgNode == nullptr) {
        COMM_LOGE(COMM_UTILS, "message node malloc failed");
        FreeSoftBusMsg(msg);
        return;
    }
    ListInit(&msgNode->node);
    msgNode->msg = msg;
    SoftBusLooperContext *context = looper->context;
    context->mtx->lock();
    if (context->stop) {
        FreeSoftBusMsg(msg);
        SoftBusFree(msgNode);
        COMM_LOGE(COMM_UTILS, "cancel post with looper is stop, name=%{public}s", context->name);
        context->mtx->unlock();
        return;
    }
    if (SubmitMsgToFfrt(msgNode, looper, delayMicros) != SOFTBUS_OK) {
        FreeSoftBusMsg(msg);
        SoftBusFree(msgNode);
        COMM_LOGE(COMM_UTILS, "submit msg to ffrt fail, name=%{public}s", context->name);
        context->mtx->unlock();
        return;
    }
    InsertMsgWithTime(context, msgNode);
    context->msgSize++;
    if (looper->dumpable) {
        DumpLooperLocked(context);
    }
    context->mtx->unlock();
}

static void RemoveMessageWithFfrt(const SoftBusLooper *looper, const SoftBusHandler *handler,
    int (*customFunc)(const SoftBusMessage*, void*), void *args)
{
    SoftBusLooperContext *context = looper->context;
    context->mtx->lock();
    if (context->stop) {
        COMM_LOGE(COMM_UTILS, "cancel remove with looper is stop, name=%{public}s", context->name);
        context->mtx->unlock();
        return;
    }
    ListNode *item = nullptr;
    ListNode *nextItem = nullptr;
    LIST_FOR_EACH_SAFE(item, nextItem, &context->msgHead) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        SoftBusMessage *msg = itemNode->msg;
        if (msg->handler == handler && customFunc(msg, args) == 0) {
            looper->queue->msgQueue->cancel(*(itemNode->msgHandle)); // cancel fail when task is handling
            COMM_LOGD(COMM_UTILS, "remove msg with ffrt succ, time=%{public}" PRId64"", msg->time);
            FreeSoftBusMsg(msg);
            ListDelete(&itemNode->node);
            delete (itemNode->msgHandle);
            SoftBusFree(itemNode);
            context->msgSize--;
        }
    }
    context->mtx->unlock();
}

static void DestroyLooperWithFfrt(SoftBusLooper *looper)
{
    SoftBusLooperContext *context = looper->context;
    if (context != nullptr) {
        context->mtx->lock();
        context->stop = true;
        COMM_LOGI(COMM_UTILS, "looper is stop, name=%{public}s", looper->context->name);
        context->mtx->unlock();
        delete (looper->queue->msgQueue); //if task is handling when delete, it will return after handle;
        ListNode *item = nullptr;
        ListNode *nextItem = nullptr;
        LIST_FOR_EACH_SAFE(item, nextItem, &context->msgHead) {
            SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
            SoftBusMessage *msg = itemNode->msg;
            FreeSoftBusMsg(msg);
            ListDelete(&itemNode->node);
            delete (itemNode->msgHandle);
            SoftBusFree(itemNode);
            context->msgSize--;
        }
        delete (context->mtx);
        SoftBusFree(context);
        context = nullptr;
    } else {
        delete (looper->queue->msgQueue);
    }
    SoftBusFree(looper->queue);
    ReleaseLooper(looper);
    SoftBusFree(looper);
    if (g_looperCnt.load(std::memory_order_acquire) != 0) {
        g_looperCnt--;
    }
}

static void LooperPostMessage(const SoftBusLooper *looper, SoftBusMessage *msg)
{
    if (msg == nullptr || msg->handler == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessage with nullmsg");
        return;
    }
    if (looper == nullptr || looper->context == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessage with nulllooper");
        return;
    }
    if (looper->queue == nullptr || looper->queue->msgQueue == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessage with nullqueue");
        return;
    }
    msg->time = UptimeMicros();
    PostMessageWithFfrt(looper, msg, 0);
}

static void LooperPostMessageDelay(const SoftBusLooper *looper, SoftBusMessage *msg, uint64_t delayMillis)
{
    if (msg == nullptr || msg->handler == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessageDelay with nullmsg");
        return;
    }
    if (looper == nullptr || looper->context == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessageDelay with nulllooper");
        return;
    }
    if (looper->queue == nullptr || looper->queue->msgQueue == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessageDelay with nullqueue");
        return;
    }
    msg->time = UptimeMicros() + (int64_t)delayMillis * TIME_THOUSANDS_MULTIPLIER;
    PostMessageWithFfrt(looper, msg, delayMillis * TIME_THOUSANDS_MULTIPLIER);
}

static int WhatRemoveFunc(const SoftBusMessage *msg, void *args)
{
    int32_t what = (int32_t)(intptr_t)args;
    if (msg->what == what) {
        return 0;
    }
    return 1;
}

static void LoopRemoveMessageCustom(const SoftBusLooper *looper, const SoftBusHandler *handler,
    int (*customFunc)(const SoftBusMessage*, void*), void *args)
{
    if (looper == nullptr || looper->context == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperRemoveMessage with nulllopper");
        return;
    }
    if (looper->queue == nullptr || looper->queue->msgQueue == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperRemoveMessage with nullqueue");
        return;
    }
    if (handler == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperRemoveMessage with nullhandler");
        return;
    }
    if (customFunc == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperRemoveMessage with nullcustomFunc");
        return;
    }
    RemoveMessageWithFfrt(looper, handler, customFunc, args);
}

static void LooperRemoveMessage(const SoftBusLooper *looper, const SoftBusHandler *handler, int32_t what)
{
    if (looper == nullptr || looper->context == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperRemoveMessage with nulllopper");
        return;
    }
    if (looper->queue == nullptr || looper->queue->msgQueue == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperRemoveMessage with nullqueue");
        return;
    }
    if (handler == nullptr) {
        COMM_LOGE(COMM_UTILS, "LooperRemoveMessage with nullhandler");
        return;
    }
    LoopRemoveMessageCustom(looper, handler, WhatRemoveFunc, (void*)(intptr_t)what);
}

void SetLooperDumpable(SoftBusLooper *looper, bool dumpable)
{
    if (looper == nullptr || looper->context == nullptr) {
        COMM_LOGE(COMM_UTILS, "looper param is invalid");
        return;
    }
    looper->context->mtx->lock();
    looper->dumpable = dumpable;
    looper->context->mtx->unlock();
}

static int32_t CreateNewFfrtQueue(FfrtMsgQueue **ffrtQueue, const char *name)
{
    FfrtMsgQueue *tmpQueue = static_cast<FfrtMsgQueue *>(SoftBusCalloc(sizeof(FfrtMsgQueue)));
    if (tmpQueue == nullptr) {
        COMM_LOGE(COMM_UTILS, "softbus msgQueue SoftBusCalloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    tmpQueue->msgQueue = new (std::nothrow)ffrt::queue(name);
    if (tmpQueue->msgQueue == nullptr) {
        COMM_LOGE(COMM_UTILS, "ffrt msgQueue SoftBusCalloc fail");
        SoftBusFree(tmpQueue);
        return SOFTBUS_MALLOC_ERR;
    }
    *ffrtQueue = tmpQueue;
    return SOFTBUS_OK;
}

static int32_t CreateNewContext(SoftBusLooperContext **context, const char *name)
{
    SoftBusLooperContext *tmpContext = static_cast<SoftBusLooperContext *>(SoftBusCalloc(sizeof(SoftBusLooperContext)));
    if (tmpContext == nullptr) {
        COMM_LOGE(COMM_UTILS, "context SoftBusCalloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(tmpContext->name, LOOP_NAME_LEN, name, strlen(name)) != EOK) {
        COMM_LOGE(COMM_UTILS, "memcpy context name fail");
        SoftBusFree(tmpContext);
        return SOFTBUS_STRCPY_ERR;
    }
    ListInit(&tmpContext->msgHead);
    // init mtx
    tmpContext->mtx = new (std::nothrow)ffrt::mutex();
    if (tmpContext->mtx == nullptr) {
        COMM_LOGE(COMM_UTILS, "context ffrt lock init fail");
        SoftBusFree(tmpContext);
        return SOFTBUS_MALLOC_ERR;
    }
    tmpContext->stop = false;
    *context = tmpContext;
    return SOFTBUS_OK;
}

SoftBusLooper *CreateNewLooper(const char *name)
{
    if (name == nullptr || strlen(name) >= LOOP_NAME_LEN) {
        COMM_LOGE(COMM_UTILS, "invalid looper name=%{public}s", name);
        return nullptr;
    }
    if (g_looperCnt.load(std::memory_order_acquire) >= MAX_LOOPER_CNT) {
        COMM_LOGE(COMM_UTILS, "Looper exceeds the maximum, count=%{public}u,",
            g_looperCnt.load(std::memory_order_acquire));
        return nullptr;
    }
    SoftBusLooper *looper = static_cast<SoftBusLooper *>(SoftBusCalloc(sizeof(SoftBusLooper)));
    if (looper == nullptr) {
        COMM_LOGE(COMM_UTILS, "Looper SoftBusCalloc fail");
        return nullptr;
    }
    SoftBusLooperContext *context = nullptr;
    if (CreateNewContext(&context, name) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "create new context fail");
        SoftBusFree(looper);
        return nullptr;
    }
    FfrtMsgQueue *ffrtQueue = nullptr;
    if (CreateNewFfrtQueue(&ffrtQueue, name) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "create new ffrtQueue fail");
        delete (context->mtx);
        SoftBusFree(context);
        SoftBusFree(looper);
        return nullptr;
    }
    // init looper
    looper->context = context;
    looper->dumpable = true;
    looper->PostMessage = LooperPostMessage;
    looper->PostMessageDelay = LooperPostMessageDelay;
    looper->RemoveMessage = LooperRemoveMessage;
    looper->RemoveMessageCustom = LoopRemoveMessageCustom;
    looper->queue = ffrtQueue;
    COMM_LOGI(COMM_UTILS, "start looper with ffrt ok, name=%{public}s", context->name);
    g_looperCnt++;
    return looper;
}

SoftBusLooper *GetLooper(int type)
{
    uint32_t len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (uint32_t i = 0; i < len; i++) {
        if (g_loopConfig[i].type == type) {
            return g_loopConfig[i].looper;
        }
    }
    return nullptr;
}

void SetLooper(int type, SoftBusLooper *looper)
{
    uint32_t len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (uint32_t i = 0; i < len; i++) {
        if (g_loopConfig[i].type == type) {
            g_loopConfig[i].looper = looper;
        }
    }
}

void DestroyLooper(SoftBusLooper *looper)
{
    if (looper == nullptr) {
        COMM_LOGE(COMM_UTILS, "DestroyLooper with nulllooper");
        return;
    }
    if (looper->queue == nullptr || looper->queue->msgQueue == nullptr) {
        COMM_LOGE(COMM_UTILS, "DestroyLooper with nullqueue");
        return;
    }
    DestroyLooperWithFfrt(looper);
}

int LooperInit(void)
{
    SoftBusLooper *looper = CreateNewLooper("BusCenter_Lp");
    if (!looper) {
        COMM_LOGE(COMM_UTILS, "init BusCenter looper fail.");
        return SOFTBUS_LOOPER_ERR;
    }
    SetLooper(LOOP_TYPE_DEFAULT, looper);

    SoftBusLooper *connLooper = CreateNewLooper("ReactorLink_Lp");
    if (!connLooper) {
        COMM_LOGE(COMM_UTILS, "init connection looper fail.");
        return SOFTBUS_LOOPER_ERR;
    }
    SetLooper(LOOP_TYPE_CONN, connLooper);

    COMM_LOGD(COMM_UTILS, "init looper success.");
    return SOFTBUS_OK;
}

void LooperDeinit(void)
{
    uint32_t len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (uint32_t i = 0; i < len; i++) {
        if (g_loopConfig[i].looper == nullptr) {
            continue;
        }
        DestroyLooper(g_loopConfig[i].looper);
    }
}