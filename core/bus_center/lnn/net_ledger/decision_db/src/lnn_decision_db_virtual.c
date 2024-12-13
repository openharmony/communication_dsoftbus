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

#include "lnn_decision_db.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    (void)udid;

    LNN_LOGE(LNN_LEDGER, "insert trusted dev info not implemented");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId)
{
    (void)udid;
    (void)localUserId;

    LNN_LOGE(LNN_LEDGER, "remove trusted dev info not implemented");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num)
{
    (void)udidArray;
    (void)num;

    LNN_LOGE(LNN_LEDGER, "get trusted dev info not implemented");
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnIsPotentialHomeGroup(const char *udid)
{
    (void)udid;

    LNN_LOGE(LNN_LEDGER, "check is potential home group not implemented");
    return false;
}

int32_t LnnInitDecisionDbDelay(void)
{
    LNN_LOGE(LNN_INIT, "init decision db not implemented");
    return SOFTBUS_OK;
}

int32_t LnnGenerateCeParams(void)
{
    LNN_LOGI(LNN_INIT, "LnnGenerateCeParams not implemented");
    return SOFTBUS_OK;
}

int32_t UpdateRecoveryDeviceInfoFromDb(void)
{
    return SOFTBUS_OK;
}

int32_t LnnCheckGenerateSoftBusKeyByHuks(void)
{
    LNN_LOGI(LNN_INIT, "check generate softbus key by huks not implemented");
    return SOFTBUS_OK;
}
