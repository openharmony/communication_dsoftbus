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
#include "softbus_conn_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AUTH_APPID "softbus_auth"

/* auth timeout delay */
#define AUTH_DELAY_MS (10 * 1000)

/* auth data max length */
#define AUTH_MAX_DATA_LEN (64 * 1024)

/* the length of the groupID */
#define GROUPID_BUF_LEN 65

/* group type */
#define IDENTICAL_ACCOUNT_GROUP 1

/* auth status */
#define INIT_STATE 0
#define WAIT_CONNECTION_ESTABLISHED 1
#define IN_AUTH_PROGRESS 2
#define IN_SYNC_PROGRESS 3
#define SYNC_FINISH 4
#define WAIT_PEER_DEV_INFO 5
#define WAIT_CLOSE_ACK 6
#define AUTH_PASSED 7


typedef struct {
    uint32_t type;
    int32_t module;
    int64_t seq;
    int32_t flag;
    uint32_t dataLen;
} AuthDataInfo;

typedef struct {
    uint32_t requestId;
    uint32_t connectionId;

    int64_t authId;
    AuthSideFlag side;
    uint8_t status;
    uint16_t id;
    int32_t fd;
    ConnectOption option;
    int32_t encryptInfoStatus;

    const GroupAuthManager *hichain;
    VerifyCallback *cb;

    AuthConnCallback connCb;
    bool isAuthP2p;

    char peerP2pMac[MAC_LEN];
    char peerUdid[UDID_BUF_LEN];
    char peerUuid[UUID_BUF_LEN];
    char peerUid[MAX_ACCOUNT_HASH_LEN];
    int32_t softbusVersion;
    SoftBusVersion peerVersion;

    uint8_t *encryptDevData;
    uint32_t encryptLen;
    bool isValid;
    uint64_t timeStamp;

    ListNode node;
} AuthManager;

AuthManager *AuthGetManagerByRequestId(uint32_t requestId);
AuthManager *AuthGetManagerByAuthId(int64_t authId);
AuthManager *AuthGetManagerByConnId(uint16_t id);
AuthManager *AuthGetManagerByFd(int32_t fd);
AuthManager *AuthGetManagerByConnectionId(uint32_t connectionId);
int32_t CreateServerIpAuth(int32_t cfd, const char *ip, int32_t port);
void AuthHandlePeerSyncDeviceInfo(AuthManager *auth, uint8_t *data, uint32_t len);
void HandleReceiveDeviceId(AuthManager *auth, uint8_t *data);
void HandleReceiveAuthData(AuthManager *auth, int32_t module, uint8_t *data, uint32_t dataLen);
void AuthNotifyLnnDisconn(const AuthManager *auth);
void AuthNotifyTransDisconn(int64_t authId);
void AuthHandleTransInfo(const AuthManager *auth, const ConnPktHead *head, char *data);
void AuthHandleFail(AuthManager *auth, int32_t reason);
int32_t GetActiveAuthConnInfo(const char *uuid, ConnectType type, AuthConnInfo *connInfo);

#ifdef __cplusplus
}
#endif
#endif /* AUTH_MANAGER_H */
