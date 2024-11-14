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

#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hidumper_bc_mgr.h"

#define SOFTBUS_BC_MGR_MODULE_NAME "broadcastMgr"
#define SOFTBUS_BC_MGR_MODULE_HELP "List all the dump item of broadcastMgr"

static LIST_HEAD(g_bcMgr_var_list);

int32_t SoftBusRegBcMgrVarDump(const char *dumpVar, SoftBusVarDumpCb cb)
{
    if (dumpVar == NULL || strlen(dumpVar) >= SOFTBUS_DUMP_VAR_NAME_LEN || cb == NULL) {
        COMM_LOGE(COMM_DFX, "SoftBusRegBcMgrDumpCb invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return SoftBusAddDumpVarToList(dumpVar, cb, &g_bcMgr_var_list);
}

static int32_t SoftBusBcMgrDumpHander(int fd, int32_t argc, const char **argv)
{
    if (fd < 0 || argc < 0 || argv == NULL) {
        COMM_LOGE(COMM_DFX, "SoftBusBcMgrDumpHander invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (argc == 0 || strcmp(argv[0], "-h") == 0) {
        SoftBusDumpSubModuleHelp(fd, SOFTBUS_BC_MGR_MODULE_NAME, &g_bcMgr_var_list);
        return SOFTBUS_OK;
    }

    if (argc == 1 && strcmp(argv[0], "-l") == 0) {
        SoftBusDumpSubModuleHelp(fd, SOFTBUS_BC_MGR_MODULE_NAME, &g_bcMgr_var_list);
        return SOFTBUS_OK;
    }
    int32_t ret = SOFTBUS_OK;
    int32_t isModuleExist = SOFTBUS_DUMP_NOT_EXIST;
    if (strcmp(argv[0], "-l") == 0) {
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_bcMgr_var_list) {
            SoftBusDumpVarNode *itemNode = LIST_ENTRY(item, SoftBusDumpVarNode, node);
            if (strcmp(itemNode->varName, argv[1]) == 0) {
                ret = itemNode->dumpCallback(fd);
                isModuleExist = SOFTBUS_DUMP_EXIST;
                break;
            }
        }
        if (isModuleExist == SOFTBUS_DUMP_NOT_EXIST) {
            SoftBusDumpErrInfo(fd, argv[1]);
            SoftBusDumpSubModuleHelp(fd, SOFTBUS_BC_MGR_MODULE_NAME, &g_bcMgr_var_list);
        }
    }

    return ret;
}

int32_t SoftBusBcMgrHiDumperInit(void)
{
    int32_t ret = SoftBusRegHiDumperHandler(SOFTBUS_BC_MGR_MODULE_NAME, SOFTBUS_BC_MGR_MODULE_HELP,
        &SoftBusBcMgrDumpHander);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_INIT, "SoftBusRegBcMgrDumpCb register fail");
    }
    return ret;
}

void SoftBusHiDumperBcMgrDeInit(void)
{
    SoftBusReleaseDumpVar(&g_bcMgr_var_list);
}
