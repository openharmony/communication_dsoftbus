/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "securec.h"
#include "common_list.h"
#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_log.h"
#include "softbus_hidumper_disc.h"
#include "softbus_hidumper_conn.h"
#include "softbus_hidumper_nstack.h"
#include "softbus_hidumper_buscenter.h"
#include "softbus_hidumper_trans.h"
#include "softbus_hidumper.h"

static LIST_HEAD(g_hidumperhander_list);

void SoftBusDumpShowHelp(int fd)
{
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd is invalid.");
        return;
    }

    SOFTBUS_DPRINTF(fd, "Usage: hidumper -s 4700 -a \"[Option]\" \n");
    SOFTBUS_DPRINTF(fd, "  Option: [-h] ");
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_hidumperhander_list) {
        HandlerNode *itemNode = LIST_ENTRY(item, HandlerNode, node);
        SOFTBUS_DPRINTF(fd, "| [");
        SOFTBUS_DPRINTF(fd, "%s", itemNode->moduleName);
        SOFTBUS_DPRINTF(fd, "]");
    }
    SOFTBUS_DPRINTF(fd, "\n");

    item = NULL;
    LIST_FOR_EACH(item, &g_hidumperhander_list) {
        HandlerNode *itemNode = LIST_ENTRY(item, HandlerNode, node);
        SOFTBUS_DPRINTF(fd, "\t\t");
        SOFTBUS_DPRINTF(fd, "%s", itemNode->moduleName);
        SOFTBUS_DPRINTF(fd, "\t\t");
        SOFTBUS_DPRINTF(fd, "%s", itemNode->helpInfo);
        SOFTBUS_DPRINTF(fd, "\n");
    }
}

void SoftBusDumpErrInfo(int fd, const char *argv)
{
    if (fd < 0 || argv == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "param is invalid.");
        return;
    }
    SOFTBUS_DPRINTF(fd, "the command %s is invalid, please input again!\n", argv);
}

void SoftBusDumpSubModuleHelp(int fd, char *moduleName, ListNode *varList)
{
    if (fd < 0 || moduleName == NULL || varList == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "param is invalid.");
        return;
    }
    SOFTBUS_DPRINTF(fd, "Usage: hidumper -s 4700 -a \" %s [Option] \n", moduleName);
    SOFTBUS_DPRINTF(fd, "  Option: [-h]  | [-l <");
    ListNode *item = NULL;
    LIST_FOR_EACH(item, varList) {
        SoftBusDumpVarNode *itemNode = LIST_ENTRY(item, SoftBusDumpVarNode, node);
        SOFTBUS_DPRINTF(fd, "%s |", itemNode->varName);
    }
    SOFTBUS_DPRINTF(fd, ">]\n");
    SOFTBUS_DPRINTF(fd, "   -h         List all the dump item in %s module\n", moduleName);
    SOFTBUS_DPRINTF(fd, "   -l <item>  Dump the item in %s module, item is nesessary\n", moduleName);
}

static SoftBusDumpVarNode *SoftBusCreateDumpVarNode(const char *varName, SoftBusVarDumpCb cb)
{
    SoftBusDumpVarNode *varNode = (SoftBusDumpVarNode *)SoftBusCalloc(sizeof(SoftBusDumpVarNode));
    if (varNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusCreateDumpVarNode malloc fail.");
        return NULL;
    }
    if (strcpy_s(varNode->varName, SOFTBUS_DUMP_VAR_NAME_LEN, varName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusCreateDumpVarNode set varName  %s fail.", varName);
        SoftBusFree(varNode);
        return NULL;
    }

    varNode->dumpCallback = cb;

    return varNode;
}

int32_t SoftBusAddDumpVarToList(const char *dumpVar, SoftBusVarDumpCb cb, ListNode *varList)
{
    if (dumpVar == NULL || strlen(dumpVar) >= SOFTBUS_DUMP_VAR_NAME_LEN || cb == NULL || varList == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusRegDiscDumpCb invalid param");
        return SOFTBUS_ERR;
    }

    SoftBusDumpVarNode *varNode = SoftBusCreateDumpVarNode(dumpVar, cb);
    if (varNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusRegDiscDumpCb node create fail");
        return SOFTBUS_ERR;
    }
    varNode->dumpCallback = cb;
    ListTailInsert(varList, &varNode->node);

    return SOFTBUS_OK;
}

void SoftBusReleaseDumpVar(ListNode *varList)
{
    if (varList == NULL) {
        return;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, varList) {
        SoftBusDumpVarNode *varNode = LIST_ENTRY(item, SoftBusDumpVarNode, node);
        ListDelete(&varNode->node);;
        SoftBusFree(varNode);
    }
}

static HandlerNode *CreateHiDumperHandlerNode(char *moduleName, char *helpInfo, DumpHandlerFunc handler)
{
    HandlerNode *handlerNode = (HandlerNode *)SoftBusCalloc(sizeof(HandlerNode));
    if (handlerNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CreateHiDumperHandlerNode malloc fail.");
        return NULL;
    }

    if (strcpy_s(handlerNode->moduleName, SOFTBUS_MODULE_NAME_LEN, moduleName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CreateHiDumperHandlerNode get moduleName fail.");
        SoftBusFree(handlerNode);
        return NULL;
    }
    if (strcpy_s(handlerNode->helpInfo, SOFTBUS_MODULE_HELP_LEN, helpInfo) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CreateHiDumperHandlerNode get helpInfo fail");
        SoftBusFree(handlerNode);
        return NULL;
    }
    handlerNode->dumpHandler = handler;

    return handlerNode;
}

void SoftBusHiDumperReleaseHandler(void)
{
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_hidumperhander_list) {
        HandlerNode *handlerNode = LIST_ENTRY(item, HandlerNode, node);
        ListDelete(&handlerNode->node);;
        SoftBusFree(handlerNode);
    }
}

int32_t SoftBusRegHiDumperHandler(char *moduleName, char *helpInfo, DumpHandlerFunc handler)
{
    if (moduleName == NULL || strlen(moduleName) >= SOFTBUS_MODULE_NAME_LEN || helpInfo == NULL ||
        strlen(helpInfo) >= SOFTBUS_MODULE_HELP_LEN || handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusRegHiDumperHandler invalid param");
        return SOFTBUS_ERR;
    }

    HandlerNode *handlerNode = CreateHiDumperHandlerNode(moduleName, helpInfo, handler);
    if (handlerNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusRegHiDumperHandler node create fail");
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_hidumperhander_list, &handlerNode->node);
    return SOFTBUS_OK;
}

int32_t SoftBusDumpDispatch(int fd, int32_t argc, const char **argv)
{
    if (fd < 0 || argc < 0 || argv == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusDumpProcess: param invalid ");
        return SOFTBUS_ERR;
    }

    if (argc <= 1 || strcmp(argv[0], "-h") == 0) {
        SoftBusDumpShowHelp(fd);
        return SOFTBUS_OK;
    }

    ListNode *item = NULL;
    int32_t isModuleExist = SOFTBUS_DUMP_NOT_EXIST;
    LIST_FOR_EACH(item, &g_hidumperhander_list) {
        HandlerNode *itemNode = LIST_ENTRY(item, HandlerNode, node);
        if (strcmp(itemNode->moduleName, argv[0]) == 0) {
            if (strcmp(argv[0], "dstream") == 0 || strcmp(argv[0], "dfinder") == 0 ||
                strcmp(argv[0], "dfile") == 0 || strcmp(argv[0], "dmsg") == 0) {
                itemNode->dumpHandler(fd, argc, argv);
            } else {
                itemNode->dumpHandler(fd, argc - 1, &argv[1]);
            }
            isModuleExist = SOFTBUS_DUMP_EXIST;
            break;
        }
    }

    if (isModuleExist == SOFTBUS_DUMP_NOT_EXIST) {
        SoftBusDumpErrInfo(fd, argv[1]);
        SoftBusDumpShowHelp(fd);
    }

    return SOFTBUS_OK;
}

int32_t SoftBusHiDumperModuleInit(void)
{
    if (SoftBusDiscHiDumperInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "init Disc HiDumper fail!");
        return SOFTBUS_ERR;
    }

    if (SoftBusConnHiDumperInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "init Conn HiDumper fail!");
        return SOFTBUS_ERR;
    }

    if (SoftBusNStackHiDumperInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "init NStack HiDumper fail!");
        return SOFTBUS_ERR;
    }

    if (SoftBusHiDumperBusCenterInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "init BusCenter HiDumper fail!");
        return SOFTBUS_ERR;
    }

    SoftBusTransDumpHandlerInit();
    return SOFTBUS_OK;
}

void SoftBusHiDumperModuleDeInit(void)
{
    SoftBusHiDumperDiscDeInit();
    SoftBusHiDumperConnDeInit();
    SoftBusHiDumperBusCenterDeInit();
    SoftBusHiDumperReleaseHandler();
}
