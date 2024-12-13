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

#include "auth_deviceprofile.h"

bool IsPotentialTrustedDeviceDp(const char *deviceIdHash)
{
    (void)deviceIdHash;
    return true;
}

bool DpHasAccessControlProfile(const char *udid, bool isNeedUserId, int32_t localUserId)
{
    (void)udid;
    (void)isNeedUserId;
    (void)localUserId;
    return false;
}

void UpdateDpSameAccount(int64_t accountId, const char *deviceId, int32_t peerUserId)
{
    (void)accountId;
    (void)deviceId;
    (void)peerUserId;
}

void DelNotTrustDevice(const char *udid)
{
    (void)udid;
}