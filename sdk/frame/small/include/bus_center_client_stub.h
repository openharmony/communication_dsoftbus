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

#ifndef BUS_CENTER_CLIENT_STUB_H
#define BUS_CENTER_CLIENT_STUB_H

#include "serializer.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t ClientOnJoinLNNResult(IpcIo *data, IpcIo *reply);
int32_t ClientOnJoinMetaNodeResult(IpcIo *data, IpcIo *reply);
int32_t ClientOnLeaveLNNResult(IpcIo *data, IpcIo *reply);
int32_t ClientOnLeaveMetaNodeResult(IpcIo *data, IpcIo *reply);
int32_t ClientOnNodeOnlineStateChanged(IpcIo *data, IpcIo *reply);
int32_t ClientOnNodeBasicInfoChanged(IpcIo *data, IpcIo *reply);
int32_t ClientOnTimeSyncResult(IpcIo *data, IpcIo *reply);
void ClientOnPublishLNNResult(IpcIo *data, IpcIo *reply);
void ClientOnRefreshLNNResult(IpcIo *data, IpcIo *reply);
void ClientOnRefreshDeviceFound(IpcIo *data, IpcIo *reply);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif