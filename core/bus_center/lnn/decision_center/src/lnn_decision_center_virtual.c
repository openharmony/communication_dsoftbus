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

#include "lnn_decision_center.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t LnnInitDecisionCenter(uint32_t version)
{
    (void)version;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "decision center init success");
    return SOFTBUS_OK;
}

void LnnDeinitDecisionCenter(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "decision center deinit success");
}

int32_t LnnDcSubscribe(DcTask *task)
{
    (void)task;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "decision center subscribe task success");
    return SOFTBUS_OK;
}

int32_t LnnDcUnsubscribe(DcTask *task)
{
    (void)task;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "decision center unsubscribe task success");
    return SOFTBUS_OK;
}

void LnnDcDispatchEvent(DcEvent *dcEvent)
{
    (void)dcEvent;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "decision center disptach event success");
}