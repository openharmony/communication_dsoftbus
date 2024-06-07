/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef AUTH_LANE_H
#define AUTH_LANE_H

#include <stdbool.h>
#include <stdint.h>

#include "auth_interface.h"
#include "lnn_lane_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t DelAuthReqInfoByAuthHandle(const AuthHandle *authHandle);
void AuthFreeLane(const AuthHandle *authHandle);
int32_t GetAuthLinkTypeList(const char *networkId, AuthLinkTypeList *linkTypeList);
int32_t GetAuthConn(const char *uuid, LaneLinkType laneType, AuthConnInfo *connInfo);
int32_t AuthAllocLane(const char *networkId, uint32_t authRequestId, AuthConnCallback *callback);
void InitAuthReqInfo(void);
void DeInitAuthReqInfo(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_LANE_H */
