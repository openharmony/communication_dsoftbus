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
#include "anonymizer.h"
#include "legacy/softbus_hidumper_alarm.h"

#include <stdio.h>
#include <string.h>

#include "comm_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "legacy/softbus_hidumper.h"
#include "legacy/softbus_hidumper_util.h"

#define SOFTBUS_CONTROL_ALARM_ORDER "control"
#define SOFTBUS_MANAGEMENT_ALARM_ORDER "management"

#define SOFTBUS_ALARM_MODULE_NAME "alert"
#define SOFTBUS_ALARM_MODULE_HELP "List all the dump item of alert"

#define TWENTY_FOUR_HOURS (24 * 60)

static void SoftBusGetAlarmInfo(int fd, AlarmRecord *record)
{
    SOFTBUS_DPRINTF(fd, "Time=%s, Type=%d", record->time, record->type);
    if (record->errorCode > 0) {
        SOFTBUS_DPRINTF(fd, ", ErrorCode=%d", record->errorCode);
    }

    if (record->callerPid > 0) {
        SOFTBUS_DPRINTF(fd, ", CallerPid=%d", record->callerPid);
    }

    if (record->linkType > 0) {
        SOFTBUS_DPRINTF(fd, ", LinkType=%d", record->linkType);
    }

    if (record->minBw > 0) {
        SOFTBUS_DPRINTF(fd, ", MinBw=%d", record->minBw);
    }

    if (record->methodId > 0) {
        SOFTBUS_DPRINTF(fd, ", MethodId=%d", record->minBw);
    }

    if (record->permissionName != NULL) {
        SOFTBUS_DPRINTF(fd, ", PermissionName=%s", record->permissionName);
    }

    if (record->sessionName != NULL) {
        char *tmpName = NULL;
        Anonymize(record->sessionName, &tmpName);
        SOFTBUS_DPRINTF(fd, ", SessionName=%s", AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
    }
    SOFTBUS_DPRINTF(fd, "\n");
}

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
        SoftBusGetAlarmInfo(fd, record);
    }
    
    SoftBusFree(result);
    return SOFTBUS_OK;
}

int32_t SoftBusAlarmHiDumperInit(void)
{
    int32_t ret = SoftBusRegHiDumperHandler(SOFTBUS_ALARM_MODULE_NAME, SOFTBUS_ALARM_MODULE_HELP,
        &SoftBusAlarmDumpHander);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "SoftBusRegAlarmDumpCb registe fail");
    }
    return ret;
}
