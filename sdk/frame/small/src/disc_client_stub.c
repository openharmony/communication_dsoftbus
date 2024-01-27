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

#include "disc_client_stub.h"

#include "client_disc_manager.h"
#include "disc_log.h"
#include "ipc_skeleton.h"
#include "softbus_errcode.h"

int32_t ClientOnDiscoverySuccess(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        DISC_LOGW(DISC_CONTROL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t subscribeId = 0;
    ReadInt32(data, &subscribeId);
    DiscClientOnDiscoverySuccess(subscribeId);
    return SOFTBUS_OK;
}

int32_t ClientOnDiscoverFailed(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        DISC_LOGW(DISC_CONTROL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t subscribeId = 0;
    int32_t failReason = 0;
    ReadInt32(data, &subscribeId);
    ReadInt32(data, &failReason);
    DiscClientOnDiscoverFailed(subscribeId, failReason);
    return SOFTBUS_OK;
}

int32_t ClientOnDeviceFound(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        DISC_LOGW(DISC_CONTROL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    const DeviceInfo *deviceInfo = (const DeviceInfo*)ReadRawData(reply, sizeof(DeviceInfo));
    if (deviceInfo == NULL) {
        return SOFTBUS_ERR;
    }
    DiscClientOnDeviceFound(deviceInfo);
    return SOFTBUS_OK;
}

int32_t ClientOnPublishSuccess(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        DISC_LOGW(DISC_CONTROL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t publishId = 0;
    ReadInt32(data, &publishId);
    DiscClientOnPublishSuccess(publishId);
    return SOFTBUS_OK;
}

int32_t ClientOnPublishFail(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        DISC_LOGW(DISC_CONTROL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t publishId = 0;
    int32_t failReason = 0;
    ReadInt32(data, &publishId);
    ReadInt32(data, &failReason);
    DiscClientOnPublishFail(publishId, failReason);
    return SOFTBUS_OK;
}
