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
#ifndef LNN_OHOS_ACCOUNT_H
#define LNN_OHOS_ACCOUNT_H

#include <stdint.h>
#include "lnn_ohos_account_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UPDATE_ACCOUNT_ONLY = 1,
    UPDATE_HEARTBEAT = 2,
    UPDATE_USER_SWITCH = 3,
} UpdateAccountReason;

int32_t LnnGetOhosAccountInfo(uint8_t *accountHash, uint32_t len);
int32_t LnnGetOhosAccountInfoByUserId(int32_t userId, uint8_t *accountHash, uint32_t len);
int32_t LnnInitOhosAccount(void);
void LnnUpdateOhosAccount(UpdateAccountReason reason);
void LnnOnOhosAccountLogout(void);
bool LnnIsDefaultOhosAccount(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_OHOS_ACCOUNT_H */