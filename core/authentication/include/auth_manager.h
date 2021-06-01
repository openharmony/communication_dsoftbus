/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "common_list.h"
#include "device_auth.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AUTH_APPID "softbus_auth"

/* auth timeout delay */
#define AUTH_DELAY_MS (10 * 1000)

/* auth data max length */
#define AUTH_MAX_DATA_LEN (2 * 1024)

/* auth status */
#define INIT_STATE 0
#define WAIT_CONNECTION_ESTABLISHED 1
#define IN_AUTH_PROGRESS 2
#define IN_SYNC_PROGRESS 3
#define SYNC_FINISH 4
#define AUTH_PASSED 5
#define AUTH_FAIL 6

typedef struct {
    uint32_t type;
    int32_t module;
    int64_t authId;
    int32_t flag;
    uint32_t dataLen;
} AuthDataInfo;

typedef struct {
    uint32_t requestId;
    uint32_t connectionId;

    int64_t authId;
    AuthSideFlag side;
    uint8_t status;
    int32_t fd;
    ConnectOption option;

    const GroupAuthManager *hichain;
    VerifyCallback *cb;

    char peerUdid[UDID_BUF_LEN];
    char peerUuid[UUID_BUF_LEN];
    int32_t softbusVersion;
    SoftBusVersion peerVersion;

    uint8_t *encryptDevData;
    uint32_t encryptLen;

    pthread_mutex_t lock;
    ListNode node;
} AuthManager;

AuthManager *AuthGetManagerByRequestId(uint32_t requestId);
AuthManager *AuthGetManagerByAuthId(int64_t authId, AuthSideFlag side);
AuthManager *AuthGetManagerByFd(int32_t fd);
void AuthHandlePeerSyncDeviceInfo(AuthManager *auth, uint8_t *data, uint32_t len);
void HandleReceiveDeviceId(AuthManager *auth, uint8_t *data);
void HandleReceiveAuthData(AuthManager *auth, int32_t module, uint8_t *data, uint32_t dataLen);

#ifdef __cplusplus
}
#endif
#endif /* AUTH_MANAGER_H */
