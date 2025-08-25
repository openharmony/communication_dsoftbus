/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_SESSION_H
#define AUTH_SESSION_H

#include "auth_common.h"
#include "auth_request.h"
#include "auth_interface.h"
#include "auth_session_key.h"
#include "common_list.h"
#include "lnn_node_info.h"
#include "lnn_p2p_info.h"
#include "lnn_state_machine.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "auth_session_fsm_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

void AuthSessionSetReSyncDeviceName(void);
int32_t AuthSessionStartAuth(const AuthParam *authParam, const AuthConnInfo *connInfo,
    const DeviceKeyId *deviceKeyId);
int32_t AuthSessionProcessDevIdData(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionPostAuthData(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionGetUdid(int64_t authSeq, char *udid, uint32_t size);
int32_t AuthSessionSaveSessionKey(int64_t authSeq, const uint8_t *key, uint32_t len);
int32_t AuthSessionHandleAuthFinish(int64_t authSeq, AclWriteState aclState);
int32_t AuthSessionHandleAuthError(int64_t authSeq, int32_t reason);
int32_t AuthSessionProcessDevInfoData(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionProcessCloseAck(int64_t authSeq, const uint8_t *data, uint32_t len);
int32_t AuthSessionProcessDevInfoDataByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len);
int32_t AuthSessionProcessCloseAckByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len);
int32_t AuthSessionProcessCancelAuthByConnId(uint64_t connId, bool isConnectServer, const uint8_t *data, uint32_t len);
int32_t AuthSessionHandleDeviceNotTrusted(const char *udid);
int32_t AuthSessionHandleDeviceDisconnected(uint64_t connId, bool isNeedDisconnect);
int32_t AuthNotifyRequestVerify(int64_t authSeq);
AuthFsm *GetAuthFsmByConnId(uint64_t connId, bool isServer, bool isConnectSide);
void AuthSessionFsmExit(void);
AuthFsm *GetAuthFsmByAuthSeq(int64_t authSeq);
char *AuthSessionGetCredId(int64_t authSeq);
int32_t AuthSessionGetAuthVersion(int64_t authSeq, int32_t *version);
bool AuthSessionGetIsSameAccount(int64_t authSeq);
int32_t AuthSessionGetUserId(int64_t authSeq);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_SESSION_H */
