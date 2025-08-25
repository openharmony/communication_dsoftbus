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

#ifndef AUTH_MANAGER_STRUCT_H
#define AUTH_MANAGER_STRUCT_H

#include <stdint.h>
#include <stdbool.h>

#include "auth_interface_struct.h"
#include "auth_session_key_struct.h"
#include "bus_center_info_key_struct.h"
#include "lnn_lane_interface_struct.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
   int64_t authId;
   bool isServer;
   /* connInfo */
   uint64_t connId[AUTH_LINK_TYPE_MAX];
   AuthConnInfo connInfo[AUTH_LINK_TYPE_MAX];
   uint64_t lastActiveTime;
   /* sessionKeyInfo */
   int64_t lastAuthSeq[AUTH_LINK_TYPE_MAX];
   uint64_t lastVerifyTime;
   SessionKeyList sessionKeyList;
   /* deviceInfo */
   char p2pMac[MAC_LEN];
   char udid[UDID_BUF_LEN];
   char uuid[UUID_BUF_LEN];
   SoftBusVersion version;
   /* authState */
   bool hasAuthPassed[AUTH_LINK_TYPE_MAX];
   ListNode node;
} AuthManager;

typedef struct {
   int32_t messageType;
   ModeCycle cycle;
} DeviceMessageParse;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_MANAGER_STRUCT_H */