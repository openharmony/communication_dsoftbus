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
#include <stdio.h>
#include <string.h>

#include "comm_log.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hidumper_broadcast.h"

#define SOFTBUS_BROADCAST_MODULE_NAME "broadcast"
#define SOFTBUS_BROADCAST_MODULE_HELP "List all the dump item of broadcast"
#define SOFTBUS_BROADCAST_DUMP_HANDLER_NAME "bc_dump_handler"
#define EVENT_BROADCAT_DUMP 0
typedef int32_t (*BroadcastExecuteFunc)(SoftbusBroadcastDumpTask cb, uint64_t delayMillis);

static bool g_isInit = false;
static SoftBusHandler g_bcDumphandler = {0};
static LIST_HEAD(g_bc_var_list);

static int32_t SoftbusBroadcastDumpLooperInit(void);

static SoftBusMessage *CreateBroadcastHandlerMsg(int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        COMM_LOGE(COMM_DFX, "create broadcast handler msg failed");
        return NULL;
    }

    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_bcDumphandler;
    msg->FreeMessage = NULL;
    msg->obj = obj;
    return msg;
}

static int32_t ExecuteBroadcastTask(SoftbusBroadcastDumpTask cb, uint64_t delayMillis)
{
    cb();
    SoftBusMessage *msg = CreateBroadcastHandlerMsg(EVENT_BROADCAT_DUMP, delayMillis, 0, (void *)cb);
    if (msg == NULL) {
        COMM_LOGE(COMM_DFX, "create msg failed");
        return SOFTBUS_MALLOC_ERR;
    }

    g_bcDumphandler.looper->PostMessageDelay(g_bcDumphandler.looper, msg, delayMillis);
    return SOFTBUS_OK;
}

int32_t SoftbusRegBroadcastDumpTask(const SoftbusBroadcastDumpTask cb, uint64_t delayMillis)
{
    if (cb == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param cb");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SoftbusBroadcastDumpLooperInit();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "init looper fail");
        return ret;
    }

    SoftBusMessage *msg = CreateBroadcastHandlerMsg(EVENT_BROADCAT_DUMP, delayMillis, 0, (void *)cb);
    if (msg == NULL) {
        COMM_LOGE(COMM_DFX, "create msg failed");
        return SOFTBUS_MALLOC_ERR;
    }

    g_bcDumphandler.looper->PostMessageDelay(g_bcDumphandler.looper, msg, delayMillis);
    return SOFTBUS_OK;
}


int32_t SoftBusRegBroadcastVarDump(const char *dumpVar, const SoftBusVarDumpCb cb)
{
    if (dumpVar == NULL || strlen(dumpVar) >= SOFTBUS_DUMP_VAR_NAME_LEN || cb == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param cb");
        return SOFTBUS_INVALID_PARAM;
    }

    return SoftBusAddDumpVarToList(dumpVar, cb, &g_bc_var_list);
}

static int32_t SoftBusBroadcastDumpHander(int fd, int32_t argc, const char **argv)
{
    if (fd < 0 || argc < 0 || argv == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (argc == 0 || strcmp(argv[0], "-h") == 0) {
        SoftBusDumpSubModuleHelp(fd, SOFTBUS_BROADCAST_MODULE_NAME, &g_bc_var_list);
        return SOFTBUS_OK;
    }

    if (argc == 1 && strcmp(argv[0], "-l") == 0) {
        SoftBusDumpSubModuleHelp(fd, SOFTBUS_BROADCAST_MODULE_NAME, &g_bc_var_list);
        return SOFTBUS_OK;
    }
    int32_t ret = SOFTBUS_OK;
    int32_t isModuleExist = SOFTBUS_DUMP_NOT_EXIST;
    if (strcmp(argv[0], "-l") == 0) {
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_bc_var_list) {
            SoftBusDumpVarNode *itemNode = LIST_ENTRY(item, SoftBusDumpVarNode, node);
            if (strcmp(itemNode->varName, argv[1]) == 0) {
                ret = itemNode->dumpCallback(fd);
                isModuleExist = SOFTBUS_DUMP_EXIST;
                break;
            }
        }
        if (isModuleExist == SOFTBUS_DUMP_NOT_EXIST) {
            SoftBusDumpErrInfo(fd, argv[1]);
            SoftBusDumpSubModuleHelp(fd, SOFTBUS_BROADCAST_MODULE_NAME, &g_bc_var_list);
        }
    }

    return ret;
}

static void BroadcastMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        COMM_LOGE(COMM_DFX, "msg is null");
        return;
    }

    if (msg->what != EVENT_BROADCAT_DUMP) {
        return;
    }
    ExecuteBroadcastTask((SoftbusBroadcastDumpTask)msg->obj, msg->arg1);
}

static int32_t SoftbusBroadcastDumpLooperInit(void)
{
    if (g_bcDumphandler.looper != NULL) {
        COMM_LOGI(COMM_DFX, "looper already inited");
        return SOFTBUS_OK;
    }
    g_bcDumphandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_bcDumphandler.looper == NULL) {
        COMM_LOGE(COMM_DFX, "get looper fail!");
        return SOFTBUS_LOOPER_ERR;
    }

    g_bcDumphandler.name = SOFTBUS_BROADCAST_DUMP_HANDLER_NAME;
    g_bcDumphandler.HandleMessage = BroadcastMsgHandler;
    return SOFTBUS_OK;
}

int32_t SoftBusHiDumperBroadcastInit(void)
{
    if (g_isInit) {
        COMM_LOGI(COMM_INIT, "already inited");
        return SOFTBUS_OK;
    }

    int32_t ret = SoftBusRegHiDumperHandler(SOFTBUS_BROADCAST_MODULE_NAME, SOFTBUS_BROADCAST_MODULE_HELP,
        &SoftBusBroadcastDumpHander);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_INIT, "SoftBusBroadcastDumpHander register fail");
        return ret;
    }

    ret = SoftbusBroadcastDumpLooperInit();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_INIT, "init broadcast hidumper looper fail");
    }
    g_isInit = true;
    return SOFTBUS_OK;
}

void SoftBusHiDumperBroadcastDeInit(void)
{
    SoftBusReleaseDumpVar(&g_bc_var_list);
    g_isInit = false;
}
