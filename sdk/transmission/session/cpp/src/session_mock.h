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

#ifndef SESSION_MOCK_H
#define SESSION_MOCK_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

int CreateSessionServerInner(const char *pkgName, const char *sessionName);
int RemoveSessionServerInner(const char *pkgName, const char *sessionName);
int OpenSessionInner(const char *mySessionName, const char *peerSessionName, const char *peerNetworkId,
    const char *groupId, int flag);
void CloseSessionInner(int sessionId);
int32_t GrantPermissionInner(int uid, int pid, const char *busName);
int32_t RemovePermissionInner(const char *busName);
int32_t SendBytesInner(int32_t sessionId, const void *data, uint32_t len);
int32_t GetPeerUidInner(int32_t sessionId, int *data);
int32_t GetPeerPidInner(int32_t sessionId, int *data);
int32_t IsServerSideInner(int32_t sessionId, int *data);
int32_t GetMySessionNameInner(int32_t sessionId, char *data, uint16_t len);
int32_t GetPeerSessionNameInner(int32_t sessionId, char *data, uint16_t len);
int32_t GetPeerDeviceIdInner(int32_t sessionId, char *data, uint16_t len);
int32_t GetPkgNameInner(int32_t sessionId, char *data, uint16_t len);
#ifdef __cplusplus
}
#endif
#endif // SESSION_MOCK_H