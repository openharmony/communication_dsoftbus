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
#include <string.h>
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_hidumper.h"
#include "softbus_hidumper_interface.h"

int SoftBusDumpProcess(int fd, int argc, const char **argv)
{
    if (fd <= 0 || argv == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusDumpProcess: param invalid ");
        return SOFTBUS_ERR;
    }

    if (argc == 0 || strcmp(argv[0], "-h")) {
        SoftBusDumpShowHelp(fd);
        return SOFTBUS_OK;
    }

    const char **argvPtr = NULL;
    if (argc == 1) {
        *argvPtr = NULL;
    } else {
        argvPtr = &argv[1];
    }
    int argcNew = argc - 1;

    ListNode *item = NULL;
    ListNode *hidumperHandlerList = SoftBusGetHiDumpHandler();
    int isModuleExist = SOFTBUS_DUMP_NOT_EXIST;
    LIST_FOR_EACH(item, hidumperHandlerList) {
        HandlerNode *itemNode = LIST_ENTRY(item, HandlerNode, node);
        if (strcmp(itemNode->moduleName, argv[0]) == 0) {
            itemNode->dumpHandler(fd, argcNew, argvPtr);
            isModuleExist = SOFTBUS_DUMP_EXIST;
            break;
        }
    }

    if (isModuleExist == SOFTBUS_DUMP_NOT_EXIST) {
        SoftBusDumpErrInfo(fd, argv[0]);
        SoftBusDumpShowHelp(fd);
    }
    
    return SOFTBUS_OK;
}
