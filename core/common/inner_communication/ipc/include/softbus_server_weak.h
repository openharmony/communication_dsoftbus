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

#ifndef SOFTBUS_SERVER_WEAK_H
#define SOFTBUS_SERVER_WEAK_H

#include "liteipc_adapter.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* Server Implement function */
int __attribute__ ((weak)) ServerPublishService(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerUnPublishService(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerCreateSessionServer(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerRemoveSessionServer(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerOpenSession(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerCloseSession(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerSendSessionMsg(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerCreateChannelServer(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerRemoveChannelServer(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerSendChannelMsg(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerStartDiscovery(void *origin, IpcIo *req, IpcIo *reply);

int __attribute__ ((weak)) ServerStopDiscovery(void *origin, IpcIo *req, IpcIo *reply);

/* Server Invoke function */
int __attribute__((weak)) ClientIpcOnChannelOpened(const void *channel);

int __attribute__((weak)) ClientIpcOnChannelClosed(int32_t channelId);

int __attribute__((weak)) ClientIpcOnChannelMsgReiceived(int32_t channelId, const void *data, unsigned int len);

int __attribute__((weak)) ClientIpcOnJoinLNNResult(void *addr, const char *networkId, int32_t retCode);

int __attribute__((weak)) ClientIpcOnLeaveLNNResult(const char *networkId, int32_t retCode);

int __attribute__((weak)) ClientIpcOnNodeOnlineStateChanged(bool isOnline, void *info);

int __attribute__((weak)) ClientIpcOnNodeBasicInfoChanged(void *info, int32_t type);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SOFTBUS_SERVER_WEAK_H