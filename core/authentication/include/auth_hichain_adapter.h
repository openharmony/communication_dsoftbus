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

#ifndef AUTH_HICHAIN_ADAPTER_H
#define AUTH_HICHAIN_ADAPTER_H

#include "device_auth.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    AUTH_GROUP_ACCOUNT = 0x001,
    AUTH_GROUP_P2P = 0x100,
    AUTH_GROUP_MESH = 0x101,
    AUTH_GROUP_COMPATIBLE = 0x200,
} HichainGroup;

typedef enum {
    ID_TYPE_UNKNOWN = 0,
    ID_TYPE_DEVID,
    ID_TYPE_UID,
} TrustedRelationIdType;

int32_t RegChangeListener(const char *appId, DataChangeListener *listener);
int32_t UnregChangeListener(const char *appId);
int32_t AuthDevice(int64_t authReqId, const char *authParams, const DeviceAuthCallback *cb);
int32_t ProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len, DeviceAuthCallback *cb);
bool CheckDeviceInGroupByType(const char *udid, const char *uuid, HichainGroup groupType);
bool CheckHasRelatedGroupInfo(HichainGroup groupType);
void DestroyDeviceAuth(void);
bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId, bool isPrecise, bool isPointToPoint);
bool IsSameAccountGroupDevice(void);
void CancelRequest(int64_t authReqId, const char *appId);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_HICHAIN_ADAPTER_H */