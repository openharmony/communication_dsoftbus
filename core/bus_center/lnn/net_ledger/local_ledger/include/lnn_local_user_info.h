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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LNN_LOCAL_USER_INFO_H
#define LNN_LOCAL_USER_INFO_H

#include "lnn_node_info_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAIN_SCREEN_USER_TYPE 1
#define OTHER_SCREEN_USER_TYPE 0

int32_t LnnInitLocalUserLedger(void);
void LnnDeinitLocalUserLedger(void);
int32_t LnnAddLocalUserInfo(const UserInfo *userInfo);
int32_t LnnGetUserInfoSafe(int32_t userId, UserInfo *userInfo);
const SoftBusList *LnnGetLocalUserLedger(void);
int32_t LnnResetLogoutUserInfo(void);

#ifdef __cplusplus
}
#endif

#endif // LNN_LOCAL_USER_INFO_H
