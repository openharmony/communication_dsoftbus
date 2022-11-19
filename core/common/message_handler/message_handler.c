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

#include "message_handler.h"

#include <sys/time.h>
#include <sys/types.h>

#include "common_list.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "unistd.h"

#define LOOP_NAME_LEN 16
#define TIME_THOUSANDS_MULTIPLIER 1000LL
#define MAX_LOOPER_CNT 30U

static int8_t g_isNeedDestroy = 0;
static int8_t g_isThreadStarted = 0;
static uint32_t g_looperCnt = 0;

typedef struct {
    SoftBusMessage *msg;
    ListNode node;
} SoftBusMessageNode;

struct SoftBusLooperContext {
    ListNode msgHead;
    char name[LOOP_NAME_LEN];
    volatile unsigned char stop; // destroys looper, stop =1, and running =0
    volatile unsigned char running;
    SoftBusMessage *currentMsg;
    unsigned int msgSize;
    SoftBusMutex lock;
    SoftBusMutexAttr attr;
    SoftBusCond cond;
    SoftBusCond condRunning;
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

static void FreeSoftBusMsg(SoftBusMessage *msg)
{
    if (msg->FreeMessage == NULL) {
        SoftBusFree(msg);
    } else {
        msg->FreeMessage(msg);
    }
}

SoftBusMessage *MallocMessage(void)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusMalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "malloc SoftBusMessage failed");
        return NULL;
    }
    (void)memset_s(msg, sizeof(SoftBusMessage), 0, sizeof(SoftBusMessage));
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "loop context is NULL");
        return NULL;
    }

    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "LoopTask[%s] running", context->name);

    if (SoftBusMutexLock(&context->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return NULL;
    }
    context->running = 1;
    g_isThreadStarted = 1;
    (void)SoftBusMutexUnlock(&context->lock);

    for (;;) {
        if (SoftBusMutexLock(&context->lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
            return NULL;
        }
        // wait
        if (context->stop == 1) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "LoopTask[%s], stop ==1", context->name);
            (void)SoftBusMutexUnlock(&context->lock);
            break;
        }

        if (g_isNeedDestroy == 1) {
            (void)SoftBusMutexUnlock(&context->lock);
            break;
        }

        if (IsListEmpty(&context->msgHead)) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "LoopTask[%s] wait msg list empty", context->name);
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
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG,
                    "LoopTask[%s], get message. handle=%s,what=%" PRId32 ",arg1=%" PRIu64 ",msgSize=%u", context->name,
                    msg->handler->name, msg->what, msg->arg1, context->msgSize);
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
        (void)SoftBusMutexUnlock(&context->lock);
        if (looper->dumpable) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG,
                "LoopTask[%s], HandleMessage message. handle=%s,what=%" PRId32, context->name, msg->handler->name,
                msg->what);
        }

        if (msg->handler->HandleMessage != NULL) {
            msg->handler->HandleMessage(msg);
        }
        if (looper->dumpable) {
            // Don`t print msg->handler, msg->handler->HandleMessage() may remove handler,
            // so msg->handler maybe invalid pointer
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO,
                "LoopTask[%s], after HandleMessage message. what=%" PRId32 ",arg1=%" PRIu64,
                context->name, msg->what, msg->arg1);
        }
        (void)SoftBusMutexLock(&context->lock);
        FreeSoftBusMsg(msg);
        context->currentMsg = NULL;
        (void)SoftBusMutexUnlock(&context->lock);
    }
    (void)SoftBusMutexLock(&context->lock);
    context->running = 0;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "LoopTask[%s], running =0", context->name);
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
#ifdef __aarch64__
#define MAINLOOP_STACK_SIZE (2 * 1024 * 1024)
#else
#ifdef ASAN_BUILD
#define MAINLOOP_STACK_SIZE 10240
#else
#define MAINLOOP_STACK_SIZE 8192
#endif
#endif
    int ret;
    SoftBusThreadAttr threadAttr;
    SoftBusThread tid;
    SoftBusThreadAttrInit(&threadAttr);

    threadAttr.stackSize = MAINLOOP_STACK_SIZE;
    ret = SoftBusThreadCreate(&tid, &threadAttr, LoopTask, looper);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Init DeathProcTask ThreadAttr failed");
        return -1;
    }

    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "loop thread creating %s id %d", looper->context->name,
        (int)(uintptr_t)tid);
    return 0;
}

static void DumpLooperLocked(const SoftBusLooperContext *context)
{
    int i = 0;
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &context->msgHead) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        SoftBusMessage *msg = itemNode->msg;
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG,
            "DumpLooper. i=%d,handler=%s,what =%" PRId32 ",arg1=%" PRIu64 " arg2=%" PRIu64 ", time=%" PRId64,
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
    if (SoftBusMutexLock(&context->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    if (looper->dumpable) {
        DumpLooperLocked(context);
    }
    (void)SoftBusMutexUnlock(&context->lock);
}

static void PostMessageAtTime(const SoftBusLooper *looper, SoftBusMessage *msgPost)
{
    if (looper->dumpable) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG, "[%s]PostMessageAtTime what =%d time=% " PRId64 " us",
            looper->context->name, msgPost->what, msgPost->time);
    }
    if (msgPost->handler == NULL) {
        FreeSoftBusMsg(msgPost);
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "[%s]PostMessageAtTime. msg handler is null",
            looper->context->name);
        return;
    }
    SoftBusMessageNode *newNode = (SoftBusMessageNode *)SoftBusMalloc(sizeof(SoftBusMessageNode));
    if (newNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:oom", __func__);
        FreeSoftBusMsg(msgPost);
        return;
    }
    ListInit(&newNode->node);
    newNode->msg = msgPost;
    SoftBusLooperContext *context = looper->context;
    if (SoftBusMutexLock(&context->lock) != 0) {
        SoftBusFree(newNode);
        FreeSoftBusMsg(msgPost);
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    if (context->stop == 1) {
        SoftBusFree(newNode);
        FreeSoftBusMsg(msgPost);
        (void)SoftBusMutexUnlock(&context->lock);
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "[%s]PostMessageAtTime. running=%d,stop=1.",
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG, "[%s]PostMessageAtTime. insert", context->name);
        DumpLooperLocked(context);
    }
    SoftBusCondBroadcast(&context->cond);
    (void)SoftBusMutexUnlock(&context->lock);
}

static void LooperPostMessage(const SoftBusLooper *looper, SoftBusMessage *msg)
{
    msg->time = UptimeMicros();
    PostMessageAtTime(looper, msg);
}

static void LooperPostMessageDelay(const SoftBusLooper *looper, SoftBusMessage *msg, uint64_t delayMillis)
{
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
    if (SoftBusMutexLock(&context->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
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
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[%s]LooperRemoveMessage. handler=%s, what=%d,arg1=%" PRIu64
                ",time=%" PRId64, context->name, handler->name, msg->what, msg->arg1, msg->time);
            FreeSoftBusMsg(msg);
            ListDelete(&itemNode->node);
            SoftBusFree(itemNode);
            context->msgSize--;
        }
    }
    (void)SoftBusMutexUnlock(&context->lock);
}

static void LooperRemoveMessage(const SoftBusLooper *looper, const SoftBusHandler *handler, int what)
{
    LoopRemoveMessageCustom(looper, handler, WhatRemoveFunc, (void*)(intptr_t)what);
}

void SetLooperDumpable(SoftBusLooper *loop, bool dumpable)
{
    if (loop == NULL) {
        return;
    }
    loop->dumpable = dumpable;
}

SoftBusLooper *CreateNewLooper(const char *name)
{
    if (g_looperCnt >= MAX_LOOPER_CNT) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Looper count:%u, exceeds the maximum", g_looperCnt);
        return NULL;
    }
    SoftBusLooper *looper = (SoftBusLooper *)SoftBusCalloc(sizeof(SoftBusLooper));
    if (looper == NULL) {
        return NULL;
    }

    SoftBusLooperContext *context = SoftBusCalloc(sizeof(SoftBusLooperContext));
    if (context == NULL) {
        SoftBusFree(looper);
        return NULL;
    }

    if (memcpy_s(context->name, sizeof(context->name), name, strlen(name)) != EOK) {
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
        SoftBusFree(looper);
        SoftBusFree(context);
        return NULL;
    }
    g_looperCnt++;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[%s]wait looper start ok", context->name);
    return looper;
}

struct LoopConfigItem {
    int type;
    SoftBusLooper *looper;
};

static struct LoopConfigItem g_loopConfig[] = {
    {LOOP_TYPE_DEFAULT, NULL},
    {LOOP_TYPE_BR_SEND, NULL},
    {LOOP_TYPE_BR_RECV, NULL},
    {LOOP_TYPE_P2P, NULL},
    {LOOP_TYPE_LANE, NULL}
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
        return;
    }

    SoftBusLooperContext *context = looper->context;
    if (context != NULL) {
        (void)SoftBusMutexLock(&context->lock);

        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[%s]set stop = 1", context->name);
        context->stop = 1;

        SoftBusCondBroadcast(&context->cond);
        (void)SoftBusMutexUnlock(&context->lock);
        while (1) {
            (void)SoftBusMutexLock(&context->lock);
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[%s] get running = %d", context->name, context->running);
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[%s] destroy", context->name);
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
    SoftBusLooper *looper = CreateNewLooper("BusCenter");
    if (!looper) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init looper fail.");
        return -1;
    }
    SetLooper(LOOP_TYPE_DEFAULT, looper);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "init looper success.");
    return 0;
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
