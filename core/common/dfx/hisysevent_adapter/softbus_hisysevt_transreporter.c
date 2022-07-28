/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * miscservices under the License is miscservices on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "softbus_error_code.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"
#include "securec.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_adapter_hisysevent.h"

#define STATISTIC_EVT_TRANS_OPEN_SESSION_NUMBER "TRANS_OPEN_SESSION_NUMBER"
#define STATISTIC_EVT_TRANS_OPEN_SESSION_TIME_CONSUMING "TRANS_OPEN_SESSION_TIME_CONSUMING"

#define FAULT_EVT_TRANS_IPC_FAULT "TRANS_IPC_FAULT"
#define FAULT_EVT_TRANS_PERMISSION_FAULT "TRANS_PERMISSION_FAULT"
#define FAULT_EVT_TRANS_GET_LNN_FAULT "TRANS_GET_LNN_FAULT"
#define FAULT_EVT_TRANS_CHANNEL_INIT_FAULT "TRANS_CHANNEL_INIT_FAULT"
#define FAULT_EVT_TRANS_SESSION_NEGO_FAULT "TRANS_SESSION_NEGO_FAULT"

#define TRANS_PARAM_SUCCESS_CNT "SUCCESS_CNT"
#define TRANS_PARAM_FAIL_CNT "FAIL_CNT"
#define TRANS_PARAM_SUCCESS_RATE "SUCCESS_RATE"

#define TRANS_PARAM_MAX_TIME_CONSUMING "MAX_TIME_CONSUMING"
#define TRANS_PARAM_MIN_TIME_CONSUMING "MIN_TIME_CONSUMING"
#define TRANS_PARAM_AVE_TIME_CONSUMING "AVE_TIME_CONSUMING"
#define TRANS_PARAM_TIMES_UNDER_500MS "TIMES_UNDER_500MS"
#define TRANS_PARAM_TIMES_BETWEEN_500MS_1S "TIMES_BETWEEN_500MS_1S"
#define TRANS_PARAM_TIMES_BETWEEN_1S_2S "TIMES_BETWEEN_1S_2S"
#define TRANS_PARAM_TIMES_ABOVE_2S "TIMES_ABOVE_2S"