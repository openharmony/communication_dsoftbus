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

#ifndef AUTH_DEVICE_COMMON_KEY_H
#define AUTH_DEVICE_COMMON_KEY_H

#include <stdint.h>
#include <stdbool.h>
#include "auth_interface.h"
#include "auth_session_key.h"
#include "lnn_node_info.h"
#include "softbus_def.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    bool isServerSide;
    int32_t keyType;
    int64_t keyIndex;
    uint8_t deviceKey[SESSION_KEY_LENGTH];
    uint32_t keyLen;
    bool isOldKey;
} AuthDeviceKeyInfo;

void AuthLoadDeviceKey(void);
void AuthUpdateCreateTime(const char *udidHash, int32_t keyType, bool isServer);
int32_t AuthInsertDeviceKey(const NodeInfo *deviceInfo, const AuthDeviceKeyInfo *deviceKey, AuthLinkType type);
void AuthRemoveDeviceKeyByUdid(const char *udidOrHash);
int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey);
void AuthUpdateKeyIndex(const char *udidHash, int32_t keyType, int64_t index, bool isServer);
void AuthUpdateNormalizeKeyIndex(const char *udidHash, int64_t index, AuthLinkType type, SessionKey *normalizedKey,
    bool isServer);
int32_t AuthFindNormalizeKeyByServerSide(const char *udidHash, bool isServer, AuthDeviceKeyInfo *deviceKey);
int32_t AuthFindLatestNormalizeKey(const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey);
void AuthClearDeviceKey(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_DEVICE_COMMON_KEY_H */
