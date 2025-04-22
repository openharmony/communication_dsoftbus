/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef AUTH_HICHAIN_H
#define AUTH_HICHAIN_H

#include <stdbool.h>
#include <stdint.h>

#include "device_auth.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define GROUP_TYPE_ACCOUNT (1 << 0)
#define GROUP_TYPE_P2P (1 << 1)
#define GROUP_TYPE_MESH (1 << 2)
#define GROUP_TYPE_COMPATIBLE (1 << 3)
#define PC_PROOF_NON_CONSISTENT_ERRCODE 2046820418
#define MAX_CRED_ID_SIZE 65

typedef struct {
    char udid[UDID_BUF_LEN];
    char uid[MAX_ACCOUNT_HASH_LEN];
    char credId[MAX_CRED_ID_SIZE];
    int32_t userId;
    DeviceAuthCallback *cb;
} HiChainAuthParam;

typedef enum {
    HICHAIN_AUTH_DEVICE = 0,
    HICHAIN_AUTH_IDENTITY_SERVICE,
    HICHAIN_AUTH_BUTT
} HiChainAuthMode;

typedef struct {
    void (*onGroupCreated)(const char *groupId, int32_t groupType);
    void (*onGroupDeleted)(const char *groupId, int32_t groupType);
    void (*onDeviceNotTrusted)(const char *udid, int32_t localUserId);
    void (*onDeviceBound)(const char *udid, const char *groupInfo);
} TrustDataChangeListener;
int32_t RegTrustDataChangeListener(const TrustDataChangeListener *listener);
void UnregTrustDataChangeListener(void);

int32_t HichainStartAuth(int64_t authSeq, HiChainAuthParam *hiChainParam, HiChainAuthMode authMode);
int32_t HichainProcessData(int64_t authSeq, const uint8_t *data, uint32_t len, HiChainAuthMode authMode);
int32_t HichainProcessUkNegoData(
    int64_t authSeq, const uint8_t *data, uint32_t len, HiChainAuthMode authMode, DeviceAuthCallback *cb);
uint32_t HichainGetJoinedGroups(int32_t groupType);
int32_t RegHichainSaStatusListener(void);
int32_t UnRegHichainSaStatusListener(void);
void GetSoftbusHichainAuthErrorCode(uint32_t hichainErrCode, uint32_t *softbusErrCode);

void HichainCancelRequest(int64_t authReqId);
void HichainDestroy(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_HICHAIN_H */
