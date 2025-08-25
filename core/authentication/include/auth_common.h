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

#ifndef AUTH_COMMON_H
#define AUTH_COMMON_H

#include "auth_interface.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "auth_common_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t PostAuthEvent(EventType event, EventHandler handler,
    const void *obj, uint32_t size, uint64_t delayMs);
int32_t RemoveAuthEvent(EventType event, RemoveCompareFunc func, void *param);

/* Auth Lock */
bool RequireAuthLock(void);
void ReleaseAuthLock(void);

/* auth config */
bool GetConfigSupportAsServer(void);

/* auth capacity */
uint32_t GetAuthCapacity(void);

/* Common Functions */
uint8_t *DupMemBuffer(const uint8_t *buf, uint32_t size);
int64_t GenSeq(bool isServer);
uint64_t GetCurrentTimeMs(void);
const char *GetAuthSideStr(bool isServer);
bool CompareConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash);
int32_t ConvertToConnectOption(const AuthConnInfo *connInfo, ConnectOption *option);
int32_t ConvertToAuthConnInfo(const ConnectionInfo *info, AuthConnInfo *connInfo);
int32_t ConvertToAuthInfoForSle(const ConnectionInfo *info, AuthConnInfo *connInfo);
int32_t GetPeerUdidByNetworkId(const char *networkId, char *udid, uint32_t len);
int32_t GetIsExchangeUdidByNetworkId(const char *networkId, bool *isExchangeUdid);
DiscoveryType ConvertToDiscoveryType(AuthLinkType type);
AuthLinkType ConvertToAuthLinkType(DiscoveryType type);
bool CheckAuthConnInfoType(const AuthConnInfo *connInfo);
void PrintAuthConnInfo(const AuthConnInfo *connInfo);

int32_t AuthCommonInit(void);
void AuthCommonDeinit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_COMMON_H */
