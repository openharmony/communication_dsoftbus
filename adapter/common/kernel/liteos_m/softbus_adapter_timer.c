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

#include "softbus_adapter_timer.h"

#include "cmsis_os2.h"
#include "softbus_adapter_log.h"
#include "softbus_errcode.h"

#define MS_PER_SECOND 1000

void *SoftBusCreateTimer(void **timerId, void *timerFunc, unsigned int type)
{
    (void)timerId;

    void *id = osTimerNew((osTimerFunc_t)timerFunc, type, NULL, NULL);
    if (id != NULL) {
        HILOG_INFO(SOFTBUS_HILOG_ID, "create timer success");
        return id;
    }
    HILOG_ERROR(SOFTBUS_HILOG_ID, "create timer failed");
    return NULL;
}

int SoftBusStartTimer(void *timerId, unsigned int ms)
{
    if (osTimerStart(timerId, ms * osKernelGetTickFreq() / MS_PER_SECOND) != osOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "start timer failed");
        (void)osTimerDelete(timerId);
        return SOFTBUS_ERR;
    }
    HILOG_INFO(SOFTBUS_HILOG_ID, "start timer success");
    return SOFTBUS_OK;
}

int SoftBusDeleteTimer(void *timerId)
{
    if (osTimerDelete(timerId) != osOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "delete timer failed");
        return SOFTBUS_ERR;
    }
    HILOG_INFO(SOFTBUS_HILOG_ID, "delete timer success");
    return SOFTBUS_OK;
}

int SoftBusSleepMs(unsigned int ms)
{
    osDelay(ms * osKernelGetTickFreq() / MS_PER_SECOND);
    return SOFTBUS_OK;
}
