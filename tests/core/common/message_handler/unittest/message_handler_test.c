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
#include "softbus_adapter_mem.h"
#include "softbus_log.h"

#define CASE_ONE_WHAT 1
#define CASE_TWO_WHAT 2
#define CASE_THREE_WHAT 3
#define CASE_FOUR_WHAT 4

#define CASE_ARG 2
#define CASE_FOUR_POST_DELAY 10000
#define CASE_THREE_POST_DELAY 2000

#define CASE_FOUR_OBJ_SIZE 100

static void NetworkingHandleMessage(const SoftBusMessage* msg)
{
    LOG_INFO("NetworkingHandleMessage msg what=%d", msg->what);
}

static SoftBusHandler g_networkingHandler = {
    .name ="g_networkingHandler"
};

static void CustomfreeMessage(SoftBusMessage* msg)
{
    LOG_INFO("CustomfreeMessage msg=%d", msg->what);
    if (msg->what == CASE_FOUR_POST_DELAY) {
        SoftBusFree(msg->obj);
        SoftBusFree(msg);
    }
}

void TestMessageHandler(void)
{
    g_networkingHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    g_networkingHandler.HandleMessage = NetworkingHandleMessage;

    LOG_INFO("testHandler msg1");
    SoftBusMessage* msg = SoftBusCalloc(sizeof(SoftBusMessage));
    msg->what = CASE_ONE_WHAT;
    msg->arg1 = CASE_ARG;
    msg->handler = &g_networkingHandler;
    g_networkingHandler.looper->PostMessage(g_networkingHandler.looper, msg);

    LOG_INFO("testHandler msg4");
    SoftBusMessage* msg4 = SoftBusCalloc(sizeof(SoftBusMessage));
    msg4->what = CASE_FOUR_WHAT;
    msg4->arg1 = CASE_ARG;
    msg4->handler = &g_networkingHandler;
    msg4->FreeMessage = CustomfreeMessage;
    msg4->obj = SoftBusMalloc(CASE_FOUR_OBJ_SIZE);
    g_networkingHandler.looper->PostMessageDelay(g_networkingHandler.looper, msg4, CASE_FOUR_POST_DELAY);

    LOG_INFO("testHandler msg3");
    SoftBusMessage* msg3 = SoftBusCalloc(sizeof(SoftBusMessage));
    msg3->what = CASE_THREE_WHAT;
    msg3->arg1 = CASE_ARG;
    msg3->handler = &g_networkingHandler;
    g_networkingHandler.looper->PostMessageDelay(g_networkingHandler.looper, msg3, CASE_THREE_POST_DELAY);
    g_networkingHandler.looper->RemoveMessage(g_networkingHandler.looper, &g_networkingHandler, CASE_THREE_WHAT);

    LOG_INFO("testHandler msg2");
    SoftBusMessage* msg2 = SoftBusCalloc(sizeof(SoftBusMessage));
    msg2->what = CASE_TWO_WHAT;
    msg2->arg1 = CASE_ARG;
    msg2->handler = &g_networkingHandler;
    g_networkingHandler.looper->PostMessage(g_networkingHandler.looper, msg2);
}
