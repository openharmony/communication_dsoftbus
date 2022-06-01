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

#include "p2plink_loop.h"

#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define P2P_LOOP_NAME "p2ploop"
SoftBusLooper *g_p2pLooper = 0;
static SoftBusHandler g_p2pcHandler = {
    .name ="g_p2pHandler"
};

typedef struct {
    P2pLoopProcessFunc callback;
    void *cbPara;
    int32_t msgType;
} P2pCallbackInfo;

static void P2pLoopMsgHandler(SoftBusMessage *msg)
{
    if (msg == 0) {
        return;
    }

    P2pCallbackInfo *info = (P2pCallbackInfo *)msg->obj;
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLoopMsgHandler callback recv null info");
        return;
    }
    if (info->callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2pLoopMsgHandler callback function is null");
        return;
    }
    info->callback(msg->what, info->cbPara);
}


int32_t P2pLoopInit()
{
    g_p2pcHandler.looper = CreateNewLooper(P2P_LOOP_NAME);
    if (g_p2pcHandler.looper == 0) {
        return SOFTBUS_ERR;
    }
    g_p2pcHandler.HandleMessage = P2pLoopMsgHandler;
    return SOFTBUS_OK;
}

static void P2pFreeLoopMsg(SoftBusMessage *msg)
{
    if (msg != NULL) {
        if (msg->obj != NULL) {
            SoftBusFree(msg->obj);
        }
        SoftBusFree((void *)msg);
    }
}

static SoftBusMessage *P2pCreateLoopMsg(int32_t what, char *data)
{
    SoftBusMessage *msg = NULL;
    msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        return NULL;
    }
    msg->what = what;
    msg->handler = &g_p2pcHandler;
    msg->FreeMessage = P2pFreeLoopMsg;
    msg->obj = (void *)data;
    return msg;
}

int32_t P2pLoopProc(P2pLoopProcessFunc callback, void *para, P2pLoopMsg msgType)
{
    P2pCallbackInfo *cbinfo = SoftBusCalloc(sizeof(P2pCallbackInfo));
    if (cbinfo == NULL) {
        return SOFTBUS_ERR;
    }
    cbinfo->callback = callback;
    cbinfo->cbPara = para;
    SoftBusMessage *msg  = P2pCreateLoopMsg(msgType, (char *)cbinfo);
    if (msg == NULL) {
        SoftBusFree(cbinfo);
        return SOFTBUS_ERR;
    }
    g_p2pcHandler.looper->PostMessage(g_p2pcHandler.looper, msg);
    return SOFTBUS_OK;
}

int32_t P2pLoopProcDelay(P2pLoopProcessFunc callback, void *para, uint64_t delayMillis, P2pLoopMsg msgType)
{
    P2pCallbackInfo *cbinfo = SoftBusCalloc(sizeof(P2pCallbackInfo));
    if (cbinfo == NULL) {
        return SOFTBUS_ERR;
    }
    cbinfo->callback = callback;
    cbinfo->cbPara = para;
    SoftBusMessage *msg  = P2pCreateLoopMsg(msgType, (char *)cbinfo);
    if (msg == 0) {
        SoftBusFree(cbinfo);
        return SOFTBUS_ERR;
    }
    g_p2pcHandler.looper->PostMessageDelay(g_p2pcHandler.looper, msg, delayMillis);
    return SOFTBUS_OK;
}

static int32_t P2pRemoveMessageFunc(const SoftBusMessage *msg, void *para)
{
    if (para == NULL) {
        return SOFTBUS_ERR;
    }

    if (msg == NULL) {
        return SOFTBUS_ERR;
    }
    P2pCallbackInfo *info = (P2pCallbackInfo *)para;
    P2pCallbackInfo *delInfo = (P2pCallbackInfo *)msg->obj;
    if (delInfo == NULL) {
        return SOFTBUS_ERR;
    }
    if (msg->what == info->msgType) {
        if (info->callback != 0) {
            info->callback(info->msgType, delInfo->cbPara);
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int32_t P2pLoopProcDelayDel(P2pLoopProcessFunc callback, P2pLoopMsg msgType)
{
    P2pCallbackInfo cbinfo = {0};

    cbinfo.callback = callback;
    cbinfo.cbPara = NULL;
    cbinfo.msgType = (int32_t)msgType;

    g_p2pcHandler.looper->RemoveMessageCustom(g_p2pcHandler.looper, &g_p2pcHandler,
                                              P2pRemoveMessageFunc, (void*)&cbinfo);
    return SOFTBUS_OK;
}