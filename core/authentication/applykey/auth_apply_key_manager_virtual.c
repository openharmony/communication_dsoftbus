/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permission and
 * limitations under the License.
 */

#include "auth_apply_key_manager.h"

int32_t InitApplyKeyManager(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

void DeInitApplyKeyManager(void) { }

int32_t AuthInsertApplyKey(const RequestBusinessInfo *info, const uint8_t *uk, uint32_t ukLen, uint64_t time)
{
    (void)info;
    (void)uk;
    (void)ukLen;
    (void)time;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetApplyKeyByBusinessInfo(const RequestBusinessInfo *info, uint8_t *uk, uint32_t ukLen)
{
    (void)info;
    (void)uk;
    (void)ukLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthDeleteApplyKey(const RequestBusinessInfo *info)
{
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthRecoveryApplyKey(void) { }