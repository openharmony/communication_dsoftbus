/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "auth_apply_key_process.h"

#include "auth_log.h"

int32_t InitApplyKeyManager(void)
{
    AUTH_LOGI(AUTH_CONN, "not support");
    return SOFTBUS_OK;
}

void DeInitApplyKeyManager(void)
{
    AUTH_LOGI(AUTH_CONN, "not support");
}

int32_t AuthInsertApplyKey(
    const RequestBusinessInfo *info, const uint8_t *uk, uint32_t ukLen, uint64_t time, char *accountHash)
{
    (void)info;
    (void)uk;
    (void)ukLen;
    (void)time;
    (void)accountHash;
    AUTH_LOGI(AUTH_CONN, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetApplyKeyByBusinessInfo(
    const RequestBusinessInfo *info, uint8_t *uk, uint32_t ukLen, char *accountHash, uint32_t accountHashLen)
{
    (void)info;
    (void)uk;
    (void)ukLen;
    (void)accountHash;
    (void)accountHashLen;
    AUTH_LOGI(AUTH_CONN, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthDeleteApplyKey(const RequestBusinessInfo *info)
{
    (void)info;
    AUTH_LOGI(AUTH_CONN, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthRecoveryApplyKey(void)
{
    AUTH_LOGI(AUTH_CONN, "not support");
}

void AuthClearAccountApplyKey(void)
{
    AUTH_LOGI(AUTH_CONN, "not support");
}

int32_t AuthFindApplyKey(
    const RequestBusinessInfo *info, uint8_t *applyKey, char *accountHash, uint32_t accountHashLen)
{
    (void)info;
    (void)applyKey;
    (void)accountHash;
    (void)accountHashLen;
    AUTH_LOGI(AUTH_CONN, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGenApplyKey(
    const RequestBusinessInfo *info, uint32_t requestId, uint32_t connId, const GenApplyKeyCallback *genCb)
{
    (void)info;
    (void)requestId;
    (void)connId;
    (void)genCb;
    AUTH_LOGI(AUTH_CONN, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

uint32_t GenApplyKeySeq(void)
{
    AUTH_LOGI(AUTH_CONN, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

bool AuthIsApplyKeyExpired(uint64_t time)
{
    (void)time;
    AUTH_LOGI(AUTH_CONN, "not support");
    return true;
}

int32_t ApplyKeyNegoInit(void)
{
    AUTH_LOGI(AUTH_CONN, "not support");
    return SOFTBUS_OK;
}

void ApplyKeyNegoDeinit(void)
{
    AUTH_LOGI(AUTH_CONN, "not support");
}