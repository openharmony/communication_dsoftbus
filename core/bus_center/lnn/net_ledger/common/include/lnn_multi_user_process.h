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

#ifndef LNN_MULTI_USER_PROCESS_H
#define LNN_MULTI_USER_PROCESS_H

#include "lnn_node_info.h"
#include "softbus_json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t PackUserInfoToJsonInner(cJSON *json, const UserInfo *userInfo);
int32_t LnnAsyncCallMultiUserAllDataSyncToDB(const NodeInfo *info);
int32_t HbMultiUserHandleLogin(void);
int32_t HbMultiUserHandleLogout(void);
void RestoreLocalUserInfo(void);
void HbCheckSingleUser(int32_t userId);
void HbCheckAllForegroundUsers(void);

#ifdef __cplusplus
}
#endif

#endif /* LNN_MULTI_USER_PROCESS_H */