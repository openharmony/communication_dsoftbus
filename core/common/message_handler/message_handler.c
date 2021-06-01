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
#include "pthread.h"
#include "securec.h"
#include "softbus_def.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_type_def.h"
#include "unistd.h"

#define LOOP_NAME_LEN 16
#define TIME_THOUSANDS_MULTIPLIER 1000LL

static int8_t g_isNeedDestroy = 0;
static int8_t g_isThreadStarted = 0;

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
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
    pthread_cond_t cond;
    pthread_cond_t condRunning;
};

static uint64_t UptimeMicros(void)
{
    struct timeval t;
    t.tv_sec = 0;
    t.tv_usec = 0;
    gettimeofday(&t, NULL);
    uint64_t when = ((uint64_t)(t.tv_sec)) * TIME_THOUSANDS_MULTIPLIER * TIME_THOUSANDS_MULTIPLIER +
        (uint64_t)t.tv_usec;
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
        LOG_INFO("malloc SoftBusMessage failed");
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

    LOG_INFO("LoopTask[%s] running", context->name);

    if (pthread_mutex_lock(&context->lock) != 0) {
        LOG_ERR("lock failed");
        return NULL;
    }
    context->running = 1;
    g_isThreadStarted = 1;
    (void)pthread_mutex_unlock(&context->lock);

    for (;;) {
        if (pthread_mutex_lock(&context->lock) != 0) {
            LOG_ERR("lock failed");
            return NULL;
        }
        // wait
        if (context->stop == 1) {
            LOG_INFO("LoopTask[%s], stop ==1", context->name);
            (void)pthread_mutex_unlock(&context->lock);
            break;
        }

        if (g_isNeedDestroy == 1) {
            (void)pthread_mutex_unlock(&context->lock);
            break;
        }

        if (IsListEmpty(&context->msgHead)) {
            LOG_INFO("LoopTask[%s] wait msg list empty", context->name);
            pthread_cond_wait(&context->cond, &context->lock);
            (void)pthread_mutex_unlock(&context->lock);
            continue;
        }

        uint64_t now = UptimeMicros();
        ListNode *item = context->msgHead.next;
        SoftBusMessage *msg = NULL;
        SoftBusMessageNode *itemNode = CONTAINER_OF(item, SoftBusMessageNode, node);
        uint64_t time = itemNode->msg->time;
        if (now >= time) {
            msg = itemNode->msg;
            ListDelete(item);
            SoftBusFree(itemNode);
            context->msgSize--;
            LOG_INFO("LoopTask[%s], get message. handle=%s,what=%d,msgSize=%u",
                context->name, msg->handler->name, msg->what, context->msgSize);
        } else {
            uint64_t diff = time - now;
            struct timespec tv;
            tv.tv_sec = diff / TIME_THOUSANDS_MULTIPLIER / TIME_THOUSANDS_MULTIPLIER;
            tv.tv_nsec = diff % (TIME_THOUSANDS_MULTIPLIER * TIME_THOUSANDS_MULTIPLIER) * TIME_THOUSANDS_MULTIPLIER;
            pthread_cond_timedwait(&context->cond, &context->lock, &tv);
        }

        if (msg == NULL) {
            (void)pthread_mutex_unlock(&context->lock);
            continue;
        }
        context->currentMsg = msg;
        (void)pthread_mutex_unlock(&context->lock);
        LOG_INFO("LoopTask[%s], HandleMessage message. handle=%s,what=%d",
            context->name, msg->handler->name, msg->what);

        if (msg->handler->HandleMessage != NULL) {
            msg->handler->HandleMessage(msg);
        }
        LOG_INFO("LoopTask[%s], after HandleMessage message. handle=%s,what=%d",
            context->name, msg->handler->name, msg->what);
        (void)pthread_mutex_lock(&context->lock);
        FreeSoftBusMsg(msg);
        context->currentMsg = NULL;
        (void)pthread_mutex_unlock(&context->lock);
    }
    (void)pthread_mutex_lock(&context->lock);
    context->running = 0;
    LOG_INFO("LoopTask[%s], running =0", context->name);
    pthread_cond_broadcast(&context->cond);
    pthread_cond_broadcast(&context->condRunning);
    (void)pthread_mutex_unlock(&context->lock);
    if (g_isNeedDestroy == 1) {
        LooperDeinit();
    }
    return NULL;
}

static int StartNewLooperThread(SoftBusLooper *looper)
{
#define MAINLOOP_STACK_SIZE 5120
    pthread_t tid;
    pthread_attr_t threadAttr;

    pthread_attr_init(&threadAttr);
    pthread_attr_setstacksize(&threadAttr, MAINLOOP_STACK_SIZE);
    if (pthread_create(&tid, &threadAttr, LoopTask, looper) != 0) {
        LOG_ERR("create DeathProcTask failed");
        return -1;
    }

    LOG_INFO("loop thread creating %s id %d", looper->context->name, (int)tid);
    return 0;
}

static void DumpLooperLocked(const SoftBusLooperContext *context)
{
    int i = 0;
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &context->msgHead) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        SoftBusMessage *msg = itemNode->msg;
        LOG_DBG("DumpLooper. i=%d,handler=%s,what =%d,arg1=%llu arg2=%llu, time=%lld",
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
    if (pthread_mutex_lock(&context->lock) != 0) {
        LOG_ERR("lock failed");
        return;
    }
    DumpLooperLocked(context);
    (void)pthread_mutex_unlock(&context->lock);
}

static void PostMessageAtTime(const SoftBusLooper *looper, SoftBusMessage *msgPost)
{
    LOG_INFO("[%s]PostMessageAtTime what =%d time=%lld us", looper->context->name, msgPost->what, msgPost->time);
    if (msgPost->handler == NULL) {
        FreeSoftBusMsg(msgPost);
        LOG_ERR("[%s]PostMessageAtTime. msg handler is null", looper->context->name);
        return;
    }
    SoftBusMessageNode *newNode = (SoftBusMessageNode *)SoftBusMalloc(sizeof(SoftBusMessageNode));
    if (newNode == NULL) {
        FreeSoftBusMsg(msgPost);
        return;
    }
    ListInit(&newNode->node);
    newNode->msg = msgPost;
    SoftBusLooperContext *context = looper->context;
    if (pthread_mutex_lock(&context->lock) != 0) {
        SoftBusFree(newNode);
        FreeSoftBusMsg(msgPost);
        LOG_ERR("lock failed");
        return;
    }
    if (context->stop == 1) {
        SoftBusFree(newNode);
        FreeSoftBusMsg(msgPost);
        (void)pthread_mutex_unlock(&context->lock);
        LOG_ERR("[%s]PostMessageAtTime. running=%d,stop=%d", context->name, context->running, context->stop);
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
    LOG_INFO("[%s]PostMessageAtTime. insert", context->name);
    DumpLooperLocked(context);

    pthread_cond_broadcast(&context->cond);
    (void)pthread_mutex_unlock(&context->lock);
}

static void LooperPostMessage(const SoftBusLooper *looper, SoftBusMessage *msg)
{
    msg->time = UptimeMicros();
    PostMessageAtTime(looper, msg);
}

static void LooperPostMessageDelay(const SoftBusLooper *looper, SoftBusMessage *msg, uint64_t delayMillis)
{
    msg->time = UptimeMicros() + delayMillis * TIME_THOUSANDS_MULTIPLIER;
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
    if (pthread_mutex_lock(&context->lock) != 0) {
        LOG_ERR("lock failed");
        return;
    }
    if (context->running == 0 || context->stop == 1) {
        (void)pthread_mutex_unlock(&context->lock);
        return;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &context->msgHead) {
        SoftBusMessageNode *itemNode = LIST_ENTRY(item, SoftBusMessageNode, node);
        SoftBusMessage *msg = itemNode->msg;
        if (msg->handler == handler && customFunc(msg, args) == 0) {
            LOG_INFO("[%s]LooperRemoveMessage. handler=%s, what =%d",
                context->name, handler->name, msg->what);
            FreeSoftBusMsg(msg);
            ListDelete(&itemNode->node);
            SoftBusFree(itemNode);
            context->msgSize--;
        }
    }
    (void)pthread_mutex_unlock(&context->lock);
}

static void LooperRemoveMessage(const SoftBusLooper *looper, const SoftBusHandler *handler, int what)
{
    LoopRemoveMessageCustom(looper, handler, WhatRemoveFunc, (void*)(intptr_t)what);
}

SoftBusLooper *CreateNewLooper(const char *name)
{
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

    pthread_mutex_init(&context->lock, NULL);
    pthread_cond_init(&context->cond, NULL);
    pthread_cond_init(&context->condRunning, NULL);

    // init looper
    looper->context = context;
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

    LOG_INFO("[%s]wait looper start ok", context->name);
    return looper;
}

struct LoopConfigItem {
    int type;
    SoftBusLooper *looper;
};

static struct LoopConfigItem g_loopConfig[] = {
    {LOOP_TYPE_DEFAULT, NULL},
    {LOOP_TYPE_BR_SEND, NULL},
    {LOOP_TYPE_BR_RECV, NULL}
};

SoftBusLooper *GetLooper(int type)
{
    int len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (int i = 0; i < len; i++) {
        if (g_loopConfig[i].type == type) {
            return g_loopConfig[i].looper;
        }
    }
    return NULL;
}

static void SetLooper(int type, SoftBusLooper *looper)
{
    int len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (int i = 0; i < len; i++) {
        if (g_loopConfig[i].type == type) {
            g_loopConfig[i].looper = looper;
        }
    }
}

static void ReleaseLooper(const SoftBusLooper *looper)
{
    int len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (int i = 0; i < len; i++) {
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
        (void)pthread_mutex_lock(&context->lock);

        LOG_INFO("[%s]set stop = 1", context->name);
        context->stop = 1;

        pthread_cond_broadcast(&context->cond);
        (void)pthread_mutex_unlock(&context->lock);
        while (1) {
            (void)pthread_mutex_lock(&context->lock);
            LOG_INFO("[%s] get running = %d", context->name, context->running);
            if (context->running == 0) {
                (void)pthread_mutex_unlock(&context->lock);
                break;
            }
            pthread_cond_wait(&context->condRunning, &context->lock);
            (void)pthread_mutex_unlock(&context->lock);
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
        LOG_INFO("[%s] destroy", context->name);
        // destroy looper
        pthread_cond_destroy(&context->cond);
        pthread_cond_destroy(&context->condRunning);
        pthread_mutex_destroy(&context->lock);
        SoftBusFree(context);
        looper->context = NULL;
    }
    ReleaseLooper(looper);
    SoftBusFree(looper);
}

int LooperInit(void)
{
    SoftBusLooper *looper = CreateNewLooper("Loop-default");
    if (!looper) {
        LOG_ERR("init looper fail.");
        return -1;
    }
    SetLooper(LOOP_TYPE_DEFAULT, looper);
    LOG_INFO("init looper success.");
    return 0;
}

void LooperDeinit(void)
{
    int len = sizeof(g_loopConfig) / sizeof(struct LoopConfigItem);
    for (int i = 0; i < len; i++) {
        if (g_loopConfig[i].looper == NULL) {
            continue;
        }
        (void)pthread_mutex_lock(&(g_loopConfig[i].looper->context->lock));
        if (g_isThreadStarted == 0) {
            g_isNeedDestroy = 1;
            (void)pthread_mutex_unlock(&(g_loopConfig[i].looper->context->lock));
            return;
        }
        (void)pthread_mutex_unlock(&(g_loopConfig[i].looper->context->lock));
        DestroyLooper(g_loopConfig[i].looper);
    }
}
