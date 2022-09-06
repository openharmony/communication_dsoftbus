/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    void (*onGroupCreated)(const char *groupId);
    void (*onGroupDeleted)(const char *groupId);
    void (*onDeviceNotTrusted)(const char *udid);
} TrustDataChangeListener;
int32_t RegTrustDataChangeListener(const TrustDataChangeListener *listener);
void UnregTrustDataChangeListener(void);

int32_t HichainStartAuth(int64_t authSeq, const char *udid, const char *uid);
int32_t HichainProcessData(int64_t authSeq, const uint8_t *data, uint32_t len);

void HichainDestroy(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_HICHAIN_H */
