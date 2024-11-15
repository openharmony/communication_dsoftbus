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

#include "auth_device_common_key.h"
#include "softbus_error_code.h"


void AuthLoadDeviceKey(void)
{
}

void AuthUpdateCreateTime(const char *udidHash, int32_t keyType, bool isServer)
{
    (void)udidHash;
    (void)keyType;
    (void)isServer;
}

int32_t AuthInsertDeviceKey(const NodeInfo *deviceInfo, const AuthDeviceKeyInfo *deviceKey, AuthLinkType type)
{
    (void)deviceInfo;
    (void)deviceKey;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthRemoveDeviceKeyByUdid(const char *udidOrHash)
{
    (void)udidOrHash;
}

int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey)
{
    (void)udidHash;
    (void)keyType;
    (void)deviceKey;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthClearDeviceKey(void)
{
}

int32_t AuthFindLatestNormalizeKey(const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey)
{
    (void)udidHash;
    (void)deviceKey;
    (void)clearOldKey;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthUpdateNormalizeKeyIndex(const char *udidHash, int64_t index, AuthLinkType type, SessionKey *normalizedKey,
    bool isServer)
{
    (void)udidHash;
    (void)index;
    (void)type;
    (void)normalizedKey;
    (void)isServer;
}

void AuthUpdateKeyIndex(const char *udidHash, int32_t keyType, int64_t index, bool isServer)
{
    (void)udidHash;
    (void)keyType;
    (void)index;
    (void)isServer;
}

int32_t AuthFindNormalizeKeyByServerSide(const char *udidHash, bool isServer, AuthDeviceKeyInfo *deviceKey)
{
    (void)udidHash;
    (void)isServer;
    (void)deviceKey;
    return SOFTBUS_NOT_IMPLEMENT;
}
