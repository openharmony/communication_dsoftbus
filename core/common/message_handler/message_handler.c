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

#include "message_handler.h"

#include <securec.h>

#include "common_list.h"
#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define LOOP_NAME_LEN 16
#define TIME_THOUSANDS_MULTIPLIER 1000LL
#define MAX_LOOPER_CNT 30U
#define MAX_LOOPER_PRINT_CNT 64

static int8_t g_isNeedDestroy = 0;
static int8_t g_isThreadStarted = 0;
static uint32_t g_looperCnt = 0;

struct FfrtMsgQueue {
};

typedef struct {
    SoftBusMessage *msg;
    ListNode node;
} SoftBusMessageNode;

struct SoftBusLooperContext {
    char name[LOOP_NAME_LEN];
    volatile unsigned char stop; // destroys looper, stop =1, and running =0
    volatile unsigned char running;
    SoftBusMessage *currentMsg;
    unsigned int msgSize;
    SoftBusMutexAttr attr;
    SoftBusMutex lock;
    SoftBusCond cond;
    SoftBusCond condRunning;
    ListNode msgHead;
};

static int64_t UptimeMicros(void)
{
    SoftBusSysTime t;
    t.sec = 0;
    t.usec = 0;
    SoftBusGetTime(&t);
    int64_t when = t.sec * TIME_THOUSANDS_MULTIPLIER * TIME_THOUSANDS_MULTIPLIER + t.usec;
    return when;
}

NO_SANITIZE("cfi") static void FreeSoftBusMsg(SoftBusMessage *msg)
{
    if (msg->FreeMessage == NULL) {
        SoftBusFree(msg);
    } else {
        msg->FreeMessage(msg);
    }
}

SoftBusMessage *MallocMessage(void)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        COMM_LOGE(COMM_UTILS, "malloc SoftBusMessage failed");
        return NULL;
    }
    return msg;
}

void FreeMessage(SoftBusMessage *msg)
{
    if (msg != NULL) {
        FreeSoftBusMsg(msg);
    }
}

static void *LoopTask(void *arg)
{
    SoftBusLooper *looper = arg;
    SoftBusLooperContext *context = looper->context;
    if (context == NULL) {
        COMM_LOGE(COMM_UTILS, "loop context is NULL");
        return NULL;
    }

    COMM_LOGD(COMM_UTILS, "LoopTask running. name=%{public}s", context->name);

    if (SoftBusMutexLock(&context->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "lock failed");
        return NULL;
    }
    context->running = 1;
    g_isThreadStarted = 1;
    (void)SoftBusMutexUnlock(&context->lock);

    for (;;) {
        if (SoftBusMutexLock(&context->lock) != SOFTBUS_OK) {
            return NULL;
        }
        // wait
        if (context->stop == 1) {
            COMM_LOGI(COMM_UTILS, "LoopTask stop is 1. name=%{public}s", context->name);
            (void)SoftBusMutexUnlock(&context->lock);
            break;
        }

        if (g_isNeedDestroy == 1) {
            (void)SoftBusMutexUnlock(&context->lock);
            break;
        }

        if (IsListEmpty(&context->msgHead)) {
            COMM_LOGD(COMM_UTILS, "LoopTask wait msg list empty. name=%{public}s", context->name);
            SoftBusCondWait(&context->cond, &context->lock, NULL);
            (void)SoftBusMutexUnlock(&context->lock);
            continue;
        }

        int64_t now = UptimeMicros();
        ListNode *item = context->msgHead.next;
        SoftBusMessage *msg = NULL;
        SoftBusMessageNode *itemNode = CONTAINER_OF(item, SoftBusMessageNode, node);
        int64_t time = itemNode->msg->time;
        if (now >= time) {
            msg = itemNode->msg;
            ListDelete(item);
            SoftBusFree(itemNode);
            context->msgSize--;
            if (looper->dumpable) {
                COMM_LOGD(COMM_UTILS,
                    "LoopTask get message. name=%{public}s, handle=%{public}s, what=%{public}" PRId32 ", arg1=%{public}"
                    PRIu64 ", msgSize=%{public}u, time=%{public}" PRId64,
                    context->name, msg->handler ? msg->handler->name : "null", msg->what, msg->arg1, context->msgSize,
                    msg->time);
            }
        } else {
            SoftBusSysTime tv;
            tv.sec = time / TIME_THOUSANDS_MULTIPLIER / TIME_THOUSANDS_MULTIPLIER;
            tv.usec = time % (TIME_THOUSANDS_MULTIPLIER * TIME_THOUSANDS_MULTIPLIER);
            SoftBusCondWait(&context->cond, &context->lock, &tv);
        }

        if (msg == NULL) {
            (void)SoftBusMutexUnlock(&context->lock);
            continue;
        }
        context->currentMsg = msg;
        if (looper->dumpable) {
            COMM_LOGD(COMM_UTILS,
                "LoopTask HandleMessage message. name=%{public}s, handle=%{public}s, what=%{public}" PRId32,
                context->name, msg->handler ? msg->handler->name : "null", msg->what);
        }
        (void)SoftBusMutexUnlock(&context->lock);

        if (msg->handler != NULL && msg->handler->HandleMessage != NULL) {
            msg->handler->HandleMessage(msg);
        }

        (void)SoftBusMutexLock(&context->lock);
        if (looper->dumpable) {
            // Don`t print msg->handler, msg->handler->HandleMessage() may remove handler,
            // so msg->handler maybe invalid pointer
            COMM_LOGD(COMM_UTILS,
                "LoopTask after HandleMessage message. "
                "name=%{public}s, what=%{public}" PRId32 ", arg1=%{public}" PRIu64,
                context->name, msg->what, msg->arg1);
        }
        FreeSoftBusMsg(msg);
        context->currentMsg = NULL;
        (void)SoftBusMutexUnlock(&context->lock);
    }
    (void)SoftBusMutexLock(&context->lock);
    context->running = 0;
    COMM_LOGI(COMM_UTILS, "LoopTask running is 0. name=%{public}s", context->name);
    SoftBusCondBroadcast(&context->cond);
    SoftBusCondBroadcast(&context->condRunning);
    (void)SoftBusMutexUnlock(&context->lock);
    if (g_isNeedDestroy == 1) {
        LooperDeinit();
    }
    return NULL;
}

static int StartNewLooperThread(SoftBusLooper *looper)
{
#if defined(__aarch64__) || defined(__x86_64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define MAINLOOP_STACK_SIZE (2 * 1024 * 1024)
#else
#ifdef ASAN_BUILD
#define MAINLOOP_STACK_SIZE 10240
#else
#define MAINLOOP_STACK_SIZE (32 * 1024)
#endif
#endif
    SoftBusThreadAttr threadAttr;
    SoftBusThread tid;
    SoftBusThreadAttrInit(&threadAttr);
    threadAttr.taskName = looper->context->name;
    threadAttr.stackSize = MAINLOOP_STACK_SIZE;
    int32_t ret = SoftBusThreadCreate(&tid, &threadAttr, LoopTask, looper);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "Init DeathProcTask ThreadAttr failed");
        return SOFTBUS_ERR;
    }

    COMM_LOGI(COMM_UTILS, "loop thread creating. name=%{public}s, tid=%{public}d", looper->context->name,
        (int)(uintptr_t)tid);
    return SOFTBUS_OK;
}

static void DumpLooperLocked(const SoftBusLooperContext *context, const SoftBusHandler *handler)
{
    int32_t i = 0;
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &context->msgHead) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        SoftBusMessage *msg = itemNode->msg;
        if (i > MAX_LOOPER_PRINT_CNT) {
            COMM_LOGW(COMM_UTILS, "many messages left unprocessed, msgSize=%{public}u",
                context->msgSize);
            break;
        }
        if (handler != NULL && handler != msg->handler) {
            continue;
        }
        COMM_LOGD(COMM_UTILS,
            "DumpLooper. i=%{public}d, handler=%{public}s, what=%{public}" PRId32 ", arg1=%{public}" PRIu64 ", "
            "arg2=%{public}" PRIu64 ", time=%{public}" PRId64,
            i, msg->handler->name, msg->what, msg->arg1, msg->arg2, msg->time);

        i++;
    }
}

void DumpLooper(const SoftBusLooper *looper)
{
    if (looper == NULL) {
        return;
    }
    SoftBusLooperContext *context = looper->context;
    if (SoftBusMutexLock(&context->lock) != SOFTBUS_OK) {
        return;
    }
    if (looper->dumpable) {
        DumpLooperLocked(context, NULL);
    }
    (void)SoftBusMutexUnlock(&context->lock);
}

static int32_t PostMessageAtTimeParamVerify(const SoftBusLooper *looper, SoftBusMessage *msgPost)
{
    if (msgPost == NULL || msgPost->handler == NULL) {
        COMM_LOGE(COMM_UTILS, "the msgPost param is null.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (looper == NULL || looper->context == NULL) {
        COMM_LOGE(COMM_UTILS, "the looper param is null.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&looper->context->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "lock looper context failed.");
        return SOFTBUS_LOCK_ERR;
    }

    if (looper->dumpable) {
        COMM_LOGD(COMM_UTILS, "PostMessageAtTime name=%{public}s, what=%{public}d, time=%{public}" PRId64 "us",
            looper->context->name, msgPost->what, msgPost->time);
    }

    (void)SoftBusMutexUnlock(&looper->context->lock);
    return SOFTBUS_OK;
}

static void PostMessageAtTime(const SoftBusLooper *looper, SoftBusMessage *msgPost)
{
    if (PostMessageAtTimeParamVerify(looper, msgPost) != SOFTBUS_OK) {
        FreeSoftBusMsg(msgPost);
        return;
    }

    SoftBusMessageNode *newNode = (SoftBusMessageNode *)SoftBusCalloc(sizeof(SoftBusMessageNode));
    if (newNode == NULL) {
        COMM_LOGE(COMM_UTILS, "message node malloc failed.");
        FreeSoftBusMsg(msgPost);
        return;
    }
    ListInit(&newNode->node);
    newNode->msg = msgPost;
    SoftBusLooperContext *context = looper->context;
    if (SoftBusMutexLock(&context->lock) != SOFTBUS_OK) {
        SoftBusFree(newNode);
        FreeSoftBusMsg(msgPost);
        return;
    }
    if (context->stop == 1) {
        SoftBusFree(newNode);
        FreeSoftBusMsg(msgPost);
        (void)SoftBusMutexUnlock(&context->lock);
        COMM_LOGE(COMM_UTILS, "PostMessageAtTime stop is 1. name=%{public}s, running=%{public}d",
            context->name, context->running);
        return;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    bool insert = false;
    LIST_FOR_EACH_SAFE(item, nextItem, &context->msgHead) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        SoftBusMessage *msg = itemNode->msg;
        if (msg->time > msgPost->time) {
            ListTailInsert(item, &(newNode->node));
            insert = true;
            break;
        }
    }
    if (!insert) {
        ListTailInsert(&(context->msgHead), &(newNode->node));
    }
    context->msgSize++;
    if (looper->dumpable) {
        COMM_LOGD(COMM_UTILS, "PostMessageAtTime insert. name=%{public}s", context->name);
        DumpLooperLocked(context, msgPost->handler);
    }
    SoftBusCondBroadcast(&context->cond);
    (void)SoftBusMutexUnlock(&context->lock);
}

static void LooperPostMessage(const SoftBusLooper *looper, SoftBusMessage *msg)
{
    if (msg == NULL) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessage with nullmsg");
        return;
    }
    if (looper == NULL) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessage with nulllooper");
        return;
    }
    msg->time = UptimeMicros();
    PostMessageAtTime(looper, msg);
}

static void LooperPostMessageDelay(const SoftBusLooper *looper, SoftBusMessage *msg, uint64_t delayMillis)
{
    if (msg == NULL) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessageDelay with nullmsg");
        return;
    }
    if (looper == NULL) {
        COMM_LOGE(COMM_UTILS, "LooperPostMessageDelay with nulllooper");
        return;
    }
    msg->time = UptimeMicros() + (int64_t)delayMillis * TIME_THOUSANDS_MULTIPLIER;
    PostMessageAtTime(looper, msg);
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
    SoftBusLooperContext *context = looper->context;
    if (SoftBusMutexLock(&context->lock) != SOFTBUS_OK) {
        return;
    }
    if (context->running == 0 || context->stop == 1) {
        (void)SoftBusMutexUnlock(&context->lock);
        return;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &context->msgHead) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        SoftBusMessage *msg = itemNode->msg;
        if (msg->handler == handler && customFunc(msg, args) == 0) {
            COMM_LOGD(COMM_UTILS,
                "LooperRemoveMessage. name=%{public}s, handler=%{public}s, what=%{public}d, arg1=%{public}" PRIu64 ", "
                "time=%{public}" PRId64,
                context->name, handler->name, msg->what, msg->arg1, msg->time);
            FreeSoftBusMsg(msg);
            ListDelete(&itemNode->node);
            SoftBusFree(itemNode);
            context->msgSize--;
        }
    }
    (void)SoftBusMutexUnlock(&context->lock);
}

static void LooperRemoveMessage(const SoftBusLooper *looper, const SoftBusHandler *handler, int32_t what)
{
    LoopRemoveMessageCustom(looper, handler, WhatRemoveFunc, (void*)(intptr_t)what);
}

void SetLooperDumpable(SoftBusLooper *looper, bool dumpable)
{
    if (looper == NULL || looper->context == NULL) {
        COMM_LOGE(COMM_UTILS, "looper param is invalid");
        return;
    }

    if (SoftBusMutexLock(&looper->context->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "lock looper context failed.");
        return;
    }

    looper->dumpable = dumpable;
    (void)SoftBusMutexUnlock(&looper->context->lock);
}

SoftBusLooper *CreateNewLooper(const char *name)
{
    if (g_looperCnt >= MAX_LOOPER_CNT) {
        COMM_LOGE(COMM_UTILS, "Looper exceeds the maximum, count=%{public}u,", g_looperCnt);
        return NULL;
    }
    SoftBusLooper *looper = (SoftBusLooper *)SoftBusCalloc(sizeof(SoftBusLooper));
    if (looper == NULL) {
        COMM_LOGE(COMM_UTILS, "Looper SoftBusCalloc fail");
        return NULL;
    }

    SoftBusLooperContext *context = (SoftBusLooperContext *)SoftBusCalloc(sizeof(SoftBusLooperContext));
    if (context == NULL) {
        COMM_LOGE(COMM_UTILS, "Looper SoftBusCalloc fail");
        SoftBusFree(looper);
        return NULL;
    }
    if (memcpy_s(context->name, sizeof(context->name), name, strlen(name)) != EOK) {
        COMM_LOGE(COMM_UTILS, "memcpy_s fail");
        SoftBusFree(looper);
        SoftBusFree(context);
        return NULL;
    }
    ListInit(&context->msgHead);
    // init context
    SoftBusMutexInit(&context->lock, NULL);
    SoftBusCondInit(&context->cond);
    SoftBusCondInit(&context->condRunning);
    // init looper
    looper->context = context;
    looper->dumpable = true;
    looper->PostMessage = LooperPostMessage;
    looper->PostMessageDelay = LooperPostMessageDelay;
    looper->RemoveMessage = LooperRemoveMessage;
    looper->RemoveMessageCustom = LoopRemoveMessageCustom;
    int ret = StartNewLooperThread(looper);
    if (ret != 0) {
        COMM_LOGE(COMM_UTILS, "start fail");
        SoftBusFree(looper);
        SoftBusFree(context);
        return NULL;
    }
    g_looperCnt++;
    COMM_LOGD(COMM_UTILS, "wait looper start ok. name=%{public}s", context->name);
    return looper;
}

struct LoopConfigItem {
    int type;
    SoftBusLooper *looper;
};

static struct LoopConfigItem g_loopConfig[] = {
    {LOOP_TYPE_DEFAULT, NULL},
    {LOOP_TYPE_CONN, NULL},
    {LOOP_TYPE_LNN, NULL}
};

SoftBusLooper *GetLooper(int type)
{
    uint32_t len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (uint32_t i = 0; i < len; i++) {
        if (g_loopConfig[i].type == type) {
            return g_loopConfig[i].looper;
        }
    }
    return NULL;
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

static void ReleaseLooper(const SoftBusLooper *looper)
{
    uint32_t len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (uint32_t i = 0; i < len; i++) {
        if (g_loopConfig[i].looper == looper) {
            g_loopConfig[i].looper = NULL;
            return;
        }
    }
}

void DestroyLooper(SoftBusLooper *looper)
{
    if (looper == NULL) {
        COMM_LOGE(COMM_UTILS, "looper is null");
        return;
    }

    SoftBusLooperContext *context = looper->context;
    if (context != NULL) {
        (void)SoftBusMutexLock(&context->lock);

        COMM_LOGI(COMM_UTILS, "set stop 1. name=%{public}s", context->name);
        context->stop = 1;

        SoftBusCondBroadcast(&context->cond);
        (void)SoftBusMutexUnlock(&context->lock);
        while (1) {
            (void)SoftBusMutexLock(&context->lock);
            COMM_LOGI(COMM_UTILS, "get. name=%{public}s, running=%{public}d", context->name, context->running);
            if (context->running == 0) {
                (void)SoftBusMutexUnlock(&context->lock);
                break;
            }
            SoftBusCondWait(&context->condRunning, &context->lock, NULL);
            (void)SoftBusMutexUnlock(&context->lock);
        }
        // release msg
        ListNode *item = NULL;
        ListNode *nextItem = NULL;
        LIST_FOR_EACH_SAFE(item, nextItem, &context->msgHead) {
            SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
            SoftBusMessage *msg = itemNode->msg;
            FreeSoftBusMsg(msg);
            ListDelete(&itemNode->node);
            SoftBusFree(itemNode);
        }
        COMM_LOGI(COMM_UTILS, "destroy. name=%{public}s", context->name);
        // destroy looper
        SoftBusCondDestroy(&context->cond);
        SoftBusCondDestroy(&context->condRunning);
        SoftBusMutexDestroy(&context->lock);
        SoftBusFree(context);
        looper->context = NULL;
    }
    ReleaseLooper(looper);
    SoftBusFree(looper);
    if (g_looperCnt != 0) {
        g_looperCnt--;
    }
}

int LooperInit(void)
{
    SoftBusLooper *looper = CreateNewLooper("BusCenter_Lp");
    if (!looper) {
        COMM_LOGE(COMM_UTILS, "init BusCenter looper fail.");
        return SOFTBUS_ERR;
    }
    SetLooper(LOOP_TYPE_DEFAULT, looper);

    SoftBusLooper *connLooper = CreateNewLooper("ReactorLink_Lp");
    if (!connLooper) {
        COMM_LOGE(COMM_UTILS, "init connection looper fail.");
        return SOFTBUS_ERR;
    }
    SetLooper(LOOP_TYPE_CONN, connLooper);

    COMM_LOGD(COMM_UTILS, "init looper success.");
    return SOFTBUS_OK;
}

void LooperDeinit(void)
{
    uint32_t len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (uint32_t i = 0; i < len; i++) {
        if (g_loopConfig[i].looper == NULL) {
            continue;
        }
        (void)SoftBusMutexLock(&(g_loopConfig[i].looper->context->lock));
        if (g_isThreadStarted == 0) {
            g_isNeedDestroy = 1;
            (void)SoftBusMutexUnlock(&(g_loopConfig[i].looper->context->lock));
            return;
        }
        (void)SoftBusMutexUnlock(&(g_loopConfig[i].looper->context->lock));
        DestroyLooper(g_loopConfig[i].looper);
    }
}
