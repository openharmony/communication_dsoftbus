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

#include "disc_client_proxy.h"

#include "disc_log.h"
#include "ipc_skeleton.h"
#include "serializer.h"
#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_server_ipc_interface_code.h"

static int32_t GetSvcIdentityByPkgName(const char *pkgName, SvcIdentity *svc)
{
    struct CommonScvId svcId = {0};
    if (SERVER_GetIdentityByPkgName(pkgName, &svcId) != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "ondevice found callback failed.");
        return SOFTBUS_ERR;
    }
    svc->handle = svcId.handle;
    svc->token = svcId.token;
    svc->cookie = svcId.cookie;
    return SOFTBUS_OK;
}

int32_t ClientIpcOnDeviceFound(const char *pkgName, const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    (void)addtions;
    DISC_LOGI(DISC_CONTROL, "ondevice found ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN_EX] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN_EX, 0);
    bool ret = WriteRawData(&io, (const void*)device, sizeof(DeviceInfo));
    if (!ret) {
        DISC_LOGE(DISC_CONTROL, "Write DeviceInfo failed.");
        return SOFTBUS_ERR;
    }
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "ondevice found callback get svc failed.");
        return SOFTBUS_ERR;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_DISCOVERY_DEVICE_FOUND, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "ondevice found callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcOnDiscoverFailed(const char *pkgName, int subscribeId, int failReason)
{
    DISC_LOGI(DISC_CONTROL, "on discovery failed callback ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    bool ret = WriteInt32(&io, subscribeId);
    if (!ret) {
        DISC_LOGE(DISC_CONTROL, "Write subscribeId failed.");
        return SOFTBUS_ERR;
    }
    ret = WriteInt32(&io, failReason);
    if (!ret) {
        DISC_LOGE(DISC_CONTROL, "Write failReason failed.");
        return SOFTBUS_ERR;
    }
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "on discovery failed callback get svc failed.");
        return SOFTBUS_ERR;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_DISCOVERY_FAIL, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "on discovery failed callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcDiscoverySuccess(const char *pkgName, int subscribeId)
{
    DISC_LOGI(DISC_CONTROL, "on discovery success callback ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    bool ret = WriteInt32(&io, subscribeId);
    if (!ret) {
        DISC_LOGE(DISC_CONTROL, "Write subscribeId failed.");
        return SOFTBUS_ERR;
    }
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "on discovery success callback get svc failed.");
        return SOFTBUS_ERR;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_DISCOVERY_SUCC, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "on discovery success callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishSuccess(const char *pkgName, int publishId)
{
    DISC_LOGI(DISC_CONTROL, "on publish success callback ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    bool ret = WriteInt32(&io, publishId);
    if (!ret) {
        DISC_LOGE(DISC_CONTROL, "Write publishId failed.");
        return SOFTBUS_ERR;
    }
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "on publish success callback get svc failed.");
        return SOFTBUS_ERR;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_PUBLISH_SUCC, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "on publish success callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishFail(const char *pkgName, int publishId, int reason)
{
    DISC_LOGI(DISC_CONTROL, "on publish failed ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    bool ret = WriteInt32(&io, publishId);
    if (!ret) {
        DISC_LOGE(DISC_CONTROL, "Write publishId failed.");
        return SOFTBUS_ERR;
    }
    ret = WriteInt32(&io, reason);
    if (!ret) {
        DISC_LOGE(DISC_CONTROL, "Write reason failed.");
        return SOFTBUS_ERR;
    }
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "on publish failed callback get svc failed.");
        return SOFTBUS_ERR;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_PUBLISH_FAIL, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "on publish failed callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
