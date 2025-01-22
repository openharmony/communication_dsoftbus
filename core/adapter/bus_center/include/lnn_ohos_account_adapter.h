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

#ifndef LNN_OHOS_ACCOUNT_ADAPTER_H
#define LNN_OHOS_ACCOUNT_ADAPTER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetOsAccountId(char *id, uint32_t idLen, uint32_t *len);
int32_t GetOsAccountIdByUserId(int32_t userId, char **id, uint32_t *len);
int32_t GetCurrentAccount(int64_t *account);
int32_t GetActiveOsAccountIds(void);
bool IsActiveOsAccountUnlocked(void);
int32_t GetOsAccountUid(char *id, uint32_t idLen, uint32_t *len);

#ifdef __cplusplus
}
#endif
#endif /* LNN_OHOS_ACCOUNT_ADAPTER_H */