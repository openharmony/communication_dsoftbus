/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "softbus_hidumper_alarm.h"

#include <stdio.h>
#include <string.h>

#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_hidumper.h"
#include "softbus_hidumper_util.h"
#include "softbus_log_old.h"

#define SOFTBUS_CONTROL_ALARM_ORDER "control"
#define SOFTBUS_MANAGEMENT_ALARM_ORDER "management"

#define SOFTBUS_ALARM_MODULE_NAME "alert"
#define SOFTBUS_ALARM_MODULE_HELP "List all the dump item of alert"

#define TWENTY_FOUR_HOURS (24 * 60)

static int32_t SoftBusAlarmDumpHander(int fd, int32_t argc, const char **argv)
{
    if (fd < 0 || argc != 1 || argv == NULL) {
        return SOFTBUS_ERR;
    }

    SoftBusAlarmEvtResult *result = (SoftBusAlarmEvtResult *)SoftBusMalloc(sizeof(SoftBusAlarmEvtResult));
    if (result == NULL) {
        SOFTBUS_DPRINTF(fd, "SoftBusAlarmDumpHander result malloc fail!\n");
        return SOFTBUS_ERR;
    }
    if (strcmp(argv[0], SOFTBUS_MANAGEMENT_ALARM_ORDER) == SOFTBUS_OK) {
        if (SoftBusQueryAlarmInfo(TWENTY_FOUR_HOURS, SOFTBUS_MANAGEMENT_ALARM_TYPE, result) != SOFTBUS_OK) {
            SOFTBUS_DPRINTF(fd, "SoftBusAlarmDumpHander query fail!\n");
            SoftBusFree(result);
            return SOFTBUS_ERR;
        }
        SOFTBUS_DPRINTF(fd, "SoftBus Management Plane Alarms:\n");
    } else if (strcmp(argv[0], SOFTBUS_CONTROL_ALARM_ORDER) == SOFTBUS_OK) {
        if (SoftBusQueryAlarmInfo(TWENTY_FOUR_HOURS, SOFTBUS_CONTROL_ALARM_TYPE, result) != SOFTBUS_OK) {
            SOFTBUS_DPRINTF(fd, "SoftBusAlarmDumpHander query fail!\n");
            SoftBusFree(result);
            return SOFTBUS_ERR;
        }
        SOFTBUS_DPRINTF(fd, "SoftBus Control Plane Alarms:\n");
    } else {
        SOFTBUS_DPRINTF(fd, "SoftBusAlarmDumpHander invalid param!\n");
        SoftBusFree(result);
        return SOFTBUS_ERR;
    }

    if (result->recordSize == 0) {
        SOFTBUS_DPRINTF(fd, "SoftBusAlarmDumpHander query result is zero!\n");
        SoftBusFree(result);
        return SOFTBUS_OK;
    }
    
    for (size_t i = 0; i < result->recordSize; i++) {
        AlarmRecord *record = &result->records[i];
        if (record == NULL) {
            continue;
        }
        SOFTBUS_DPRINTF(fd, "Time=%s, Type=%d, Caller=%d, Link=%d, MinBw=%d, Method=%d, Permission=%s, Session=%s\n",
                        record->time, record->type, record->callerPid, record->linkType,
                        record->minBw, record->methodId, record->permissionName, record->sessionName);
    }
    
    SoftBusFree(result);
    return SOFTBUS_OK;
}

int32_t SoftBusAlarmHiDumperInit(void)
{
    int32_t ret = SoftBusRegHiDumperHandler(SOFTBUS_ALARM_MODULE_NAME, SOFTBUS_ALARM_MODULE_HELP,
        &SoftBusAlarmDumpHander);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftBusRegAlarmDumpCb registe fail");
    }
    return ret;
}
