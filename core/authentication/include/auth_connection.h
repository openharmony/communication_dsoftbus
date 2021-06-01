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

#ifndef AUTH_CONNECTION_H
#define AUTH_CONNECTION_H

#include "auth_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TAG "MsgGetDeviceId"
#define CMD_TAG "TECmd"
#define DATA_TAG "TEData"
#define TE_DEVICE_ID_TAG "TEDeviceId"
#define DATA_BUF_SIZE_TAG "DataBufSize"
#define CMD_GET_AUTH_INFO "getAuthInfo"
#define CMD_RET_AUTH_INFO "retAuthInfo"
#define SOFTBUS_VERSION_INFO "softbusVersion"

#define CMD_TAG_LEN 30
#define PACKET_SIZE (64 * 1024)

int32_t AuthSyncDeviceUuid(AuthManager *auth);
int32_t AuthUnpackDeviceInfo(AuthManager *auth, uint8_t *data);
char *AuthGenDeviceLevelParam(const AuthManager *auth, bool isClient);
void AuthTryCloseConnection(uint32_t connectionId);
bool AuthOnTransmit(int64_t authId, const uint8_t *data, uint32_t len);
void AuthSendCloseAck(uint32_t connectionId);

#ifdef __cplusplus
}
#endif
#endif /* AUTH_CONNECTION_H */
