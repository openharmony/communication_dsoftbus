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

#include "auth_apply_key_process.h"

int32_t AuthFindApplyKeyId(const RequestBusinessInfo *info, uint8_t *applyKey)
{
    (void)info;
    (void)applyKey;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGenApplyKeyId(
    const RequestBusinessInfo *info, uint32_t requestId, uint32_t connId, const GenApplyKeyCallback *genCb)
{
    (void)info;
    (void)requestId;
    (void)connId;
    (void)genCb;
    return SOFTBUS_NOT_IMPLEMENT;
}

uint32_t GenApplyKeySeq(void)
{
    return 0;
}

bool AuthIsApplyKeyExpired(uint64_t time)
{
    (void)time;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ApplyKeyNegoInit(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

void ApplyKeyNegoDeinit(void) { }