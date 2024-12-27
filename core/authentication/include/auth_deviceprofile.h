/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef AUTH_DEVICEPROFILE_H
#define AUTH_DEVICEPROFILE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    UPDATE_ACL_SUCC = 0,
    UPDATE_ACL_NOT_MATCH,
    GET_ALL_ACL_FAIL,
    GET_ALL_ACL_IS_EMPTY,
} UpdateDpAclResult;

bool IsPotentialTrustedDeviceDp(const char *deviceIdHash);
bool DpHasAccessControlProfile(const char *udid, bool isNeedUserId, int32_t localUserId);
void UpdateDpSameAccount(int64_t accountId, const char *deviceId, int32_t peerUserId);
void DelNotTrustDevice(const char *udid);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_DEVICEPROFILE_H */

