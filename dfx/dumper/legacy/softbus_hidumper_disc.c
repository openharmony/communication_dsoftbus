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

#include "comm_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "legacy/softbus_hidumper_disc.h"

#define SOFTBUS_DISC_MODULE_NAME "disc"
#define SOFTBUS_DISC_MODULE_HELP "List all the dump item of disc"

static LIST_HEAD(g_disc_var_list);

int32_t SoftBusRegDiscVarDump(char *dumpVar, SoftBusVarDumpCb cb)
{
    if (dumpVar == NULL || strlen(dumpVar) >= SOFTBUS_DUMP_VAR_NAME_LEN || cb == NULL) {
        COMM_LOGE(COMM_DFX, "SoftBusRegDiscDumpCb invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return SoftBusAddDumpVarToList(dumpVar, cb, &g_disc_var_list);
}

static int32_t SoftBusDiscDumpHander(int fd, int32_t argc, const char **argv)
{
    if (fd < 0 || argc < 0 || argv == NULL) {
        COMM_LOGE(COMM_DFX, "SoftBusDiscDumpHander invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (argc == 0 || strcmp(argv[0], "-h") == 0) {
        SoftBusDumpSubModuleHelp(fd, SOFTBUS_DISC_MODULE_NAME, &g_disc_var_list);
        return SOFTBUS_OK;
    }

    if (argc == 1 && strcmp(argv[0], "-l") == 0) {
        SoftBusDumpSubModuleHelp(fd, SOFTBUS_DISC_MODULE_NAME, &g_disc_var_list);
        return SOFTBUS_OK;
    }
    int32_t ret = SOFTBUS_OK;
    int32_t isModuleExist = SOFTBUS_DUMP_NOT_EXIST;
    if (strcmp(argv[0], "-l") == 0) {
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_disc_var_list) {
            SoftBusDumpVarNode *itemNode = LIST_ENTRY(item, SoftBusDumpVarNode, node);
            if (strcmp(itemNode->varName, argv[1]) == 0) {
                ret = itemNode->dumpCallback(fd);
                isModuleExist = SOFTBUS_DUMP_EXIST;
                break;
            }
        }
        if (isModuleExist == SOFTBUS_DUMP_NOT_EXIST) {
            SoftBusDumpErrInfo(fd, argv[1]);
            SoftBusDumpSubModuleHelp(fd, SOFTBUS_DISC_MODULE_NAME, &g_disc_var_list);
        }
    }

    return ret;
}

int32_t SoftBusDiscHiDumperInit(void)
{
    int32_t ret = SoftBusRegHiDumperHandler(SOFTBUS_DISC_MODULE_NAME, SOFTBUS_DISC_MODULE_HELP,
        &SoftBusDiscDumpHander);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_INIT, "SoftBusRegDiscDumpCb registe fail");
    }
    return ret;
}

void SoftBusHiDumperDiscDeInit(void)
{
    SoftBusReleaseDumpVar(&g_disc_var_list);
}