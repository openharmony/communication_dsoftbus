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

#include "lnn_cipherkey_manager.h"

#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t LnnInitCipherKeyManager(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "init virtual lnn cipherkey manager");
    return SOFTBUS_OK;
}

void LnnDeinitCipherKeyManager(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Deinit virtual lnn cipherkey manager");
}

bool GetCipherKeyByNetworkId(const char *networkId, int32_t seq, uint32_t tableIndex, unsigned char *key,
    int32_t keyLen)
{
    return true;
}

bool GetLocalCipherKey(int32_t seq, uint32_t *tableIndex, unsigned char *key, int32_t keyLen)
{
    return true;
}

