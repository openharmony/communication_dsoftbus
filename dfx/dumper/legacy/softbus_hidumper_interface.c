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
#include "comm_log.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hidumper_alarm.h"
#include "legacy/softbus_hidumper_stats.h"
#include "legacy/softbus_hidumper_util.h"
#include "legacy/softbus_hidumper.h"

int32_t SoftBusDumpProcess(int fd, int32_t argc, const char **argv)
{
    if (fd < 0 || argc < 0 || argv == NULL) {
        COMM_LOGE(COMM_DFX, "SoftBusDumpProcess: param invalid ");
        return SOFTBUS_INVALID_PARAM;
    }
    return SoftBusDumpDispatch(fd, argc, argv);
}

int32_t SoftBusHiDumperInit(void)
{
    if (SoftBusAlarmHiDumperInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_INIT, "init Alarm HiDumper fail!");
        return SOFTBUS_DFX_INIT_FAILED;
    }

    if (SoftBusHidumperUtilInit() != SOFTBUS_OK || SoftBusHiDumperModuleInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_INIT, "SoftBusHiDumperInit fail!");
        return SOFTBUS_DFX_INIT_FAILED;
    }

    if (SoftBusStatsHiDumperInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_INIT, "init Stats HiDumper fail!");
        return SOFTBUS_DFX_INIT_FAILED;
    }
    return SOFTBUS_OK;
}

void SoftBusHiDumperDeinit(void)
{
    SoftBusHiDumperModuleDeInit();
}