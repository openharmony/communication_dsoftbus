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

#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_hidumper.h"
#include "softbus_hidumper_buscenter.h"

#define SOFTBUS_BUSCENTER_MODULE_NAME  "buscenter"
#define SOFTBUS_CONN_MODULE_HELP "List all the dump item of buscenter"

static LIST_HEAD(g_busCenter_var_list);

int SoftBusRegBusCenterVarDump(char *dumpVar, SoftBusVarDumpCb cb)
{
    if (strlen(dumpVar) >= SOFTBUS_DUMP_VAR_NAME_LEN || cb == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusRegConnVarDump invalid param");
        return SOFTBUS_ERR;
    }
    int nRet = SoftBusAddDumpVarToList(dumpVar, cb, &g_busCenter_var_list);
    return nRet;
}

int SoftBusBusCenterDumpHander(int fd, int argc, const char **argv)
{
    if (fd < 0 || argc < 0 || argv == NULL) {
        return SOFTBUS_ERR;
    }

    if (argc == 0 || strcmp(argv[0], "-h") == 0) {
        SoftBusDumpSubModuleHelp(fd, SOFTBUS_BUSCENTER_MODULE_NAME, &g_busCenter_var_list);
        return SOFTBUS_OK;
    }

    if (argc == 1 && strcmp(argv[0], "-l") == 0) {
        SoftBusDumpSubModuleHelp(fd, SOFTBUS_BUSCENTER_MODULE_NAME, &g_busCenter_var_list);
        return SOFTBUS_OK;
    }
    int nRet = SOFTBUS_OK;
    int isModuleExist = SOFTBUS_DUMP_NOT_EXIST;
    if (strcmp(argv[0], "-l") == 0) {
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_busCenter_var_list) {
            SoftBusDumpVarNode *itemNode = LIST_ENTRY(item, SoftBusDumpVarNode, node);
            if (strcmp(itemNode->varName, argv[1]) == 0) {
                nRet = itemNode->dumpCallback(fd);
                isModuleExist = SOFTBUS_DUMP_EXIST;
                break;
            }
        }
    }

    if (isModuleExist == SOFTBUS_DUMP_NOT_EXIST) {
        SoftBusDumpErrInfo(fd, argv[0]);
        SoftBusDumpSubModuleHelp(fd, SOFTBUS_BUSCENTER_MODULE_NAME, &g_busCenter_var_list);
    }
    return nRet;
}

int SoftBusHiDumperBusCenterInit(void)
{
    int nRet = SOFTBUS_OK;
    nRet = SoftBusRegHiDumperHandler(
        SOFTBUS_BUSCENTER_MODULE_NAME, SOFTBUS_CONN_MODULE_HELP, &SoftBusBusCenterDumpHander);
    if (nRet == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusBusCenterDumpHander regist fail");
    }
    return nRet;
}

void SoftBusHiDumperBusCenterDeInit(void)
{
    SoftBusReleaseDumpVar(&g_busCenter_var_list);
}
