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

#include "bus_center_client_proxy.h"

#include <securec.h>
#include <stdint.h>

#include "ipc_skeleton.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"

static int32_t GetSvcIdentityByPkgName(const char *pkgName, SvcIdentity *svc)
{
    struct CommonScvId svcId = {0};
    if (SERVER_GetIdentityByPkgName(pkgName, &svcId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get bus center callback failed");
        return SOFTBUS_NETWORK_GET_SERVICE_IDENTITY_FAILED;
    }
    svc->handle = svcId.handle;
    svc->token = svcId.token;
    svc->cookie = svcId.cookie;
    return SOFTBUS_OK;
}

static int32_t GetAllClientIdentity(SvcIdentity *svc, int num)
{
    if (svc == NULL || num == 0) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    struct CommonScvId *svcId = (struct CommonScvId *)SoftBusMalloc(sizeof(struct CommonScvId) * num);
    if (svcId == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    (void)memset_s(svcId, sizeof(struct CommonScvId) * num, 0, sizeof(struct CommonScvId) * num);
    if (SERVER_GetAllClientIdentity(svcId, num) != SOFTBUS_OK) {
        SoftBusFree(svcId);
        LNN_LOGE(LNN_EVENT, "get bus center callback failed");
        return SOFTBUS_NETWORK_GET_CLIENT_IDENTITY_FAILED;
    }
    for (int i = 0; i < num; i++) {
        svc[i].handle = svcId[i].handle;
        svc[i].token = svcId[i].token;
        svc[i].cookie = svcId[i].cookie;
    }
    SoftBusFree(svcId);
    return SOFTBUS_OK;
}

int32_t ClientOnJoinLNNResult(const char *pkgName, void *addr, uint32_t addrTypeLen,
    const char *networkId, int32_t retCode)
{
    LNN_LOGI(LNN_EVENT, "enter");
    if (pkgName == NULL || addr == NULL || (retCode == 0 && networkId == NULL)) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteUint32(&io, addrTypeLen);
    WriteBuffer(&io, addr, addrTypeLen);
    WriteInt32(&io, retCode);
    if (retCode == 0) {
        WriteString(&io, networkId);
    }
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc failed");
        return SOFTBUS_NETWORK_GET_SERVICE_IDENTITY_FAILED;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_JOIN_RESULT, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "SendRequest failed, ans=%{public}d", ans);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnLeaveLNNResult(const char *pkgName, const char *networkId, int retCode)
{
    LNN_LOGI(LNN_EVENT, "enter");
    if (networkId == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&io, networkId);
    WriteInt32(&io, retCode);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc failed");
        return SOFTBUS_NETWORK_GET_SERVICE_IDENTITY_FAILED;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_LEAVE_RESULT, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "SendRequest failed, ans=%{public}d", ans);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    LNN_LOGI(LNN_EVENT, "enter");
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteBool(&io, isOnline);
    WriteUint32(&io, infoTypeLen);
    WriteBuffer(&io, info, infoTypeLen);
    int num;
    int i;
    if (SERVER_GetClientInfoNodeNum(&num) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc num failed");
        return SOFTBUS_NETWORK_GET_SERVICE_NUM_FAILED;
    }
    if (num == 0) {
        LNN_LOGE(LNN_EVENT, "svc num is 0");
        return SOFTBUS_NETWORK_GET_SERVICE_NUM_ZERO;
    }
    SvcIdentity *svc = (SvcIdentity *)SoftBusCalloc(sizeof(SvcIdentity) * num);
    if (svc == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (GetAllClientIdentity(svc, num) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc num failed");
        SoftBusFree(svc);
        return SOFTBUS_NETWORK_GET_CLIENT_IDENTITY_FAILED;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    for (i = 0; i < num; i++) {
        int32_t ans = SendRequest(svc[i], CLIENT_ON_NODE_ONLINE_STATE_CHANGED, &io, NULL, option, NULL);
        if (ans != SOFTBUS_OK) {
            LNN_LOGE(LNN_EVENT, "SendRequest failed, ans=%{public}d", ans);
            SoftBusFree(svc);
            return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
        }
    }
    SoftBusFree(svc);
    return SOFTBUS_OK;
}

int32_t ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    LNN_LOGI(LNN_EVENT, "enter");
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&io, type);
    WriteUint32(&io, infoTypeLen);
    WriteBuffer(&io, info, infoTypeLen);
    int num;
    int i;
    if (SERVER_GetClientInfoNodeNum(&num) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc num failed");
        return SOFTBUS_NETWORK_GET_SERVICE_NUM_FAILED;
    }
    if (num == 0) {
        LNN_LOGE(LNN_EVENT, "svc num NULL");
        return SOFTBUS_NETWORK_GET_SERVICE_NUM_ZERO;
    }
    SvcIdentity *svc = (SvcIdentity *)SoftBusCalloc(sizeof(SvcIdentity) * num);
    if (svc == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (GetAllClientIdentity(svc, num) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc num failed.");
        SoftBusFree(svc);
        return SOFTBUS_NETWORK_GET_CLIENT_IDENTITY_FAILED;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    for (i = 0; i < num; i++) {
        int32_t ans = SendRequest(svc[i], CLIENT_ON_NODE_BASIC_INFO_CHANGED, &io, NULL, option, NULL);
        if (ans != SOFTBUS_OK) {
            LNN_LOGE(LNN_EVENT, "SendRequest failed, ans=%{public}d", ans);
            SoftBusFree(svc);
            return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
        }
    }
    SoftBusFree(svc);
    return SOFTBUS_OK;
}

int32_t ClientOnTimeSyncResult(const char *pkgName, int32_t pid, const void *info,
    uint32_t infoTypeLen, int32_t retCode)
{
    (void)pid;
    LNN_LOGI(LNN_EVENT, "enter");
    if (pkgName == NULL || info == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteUint32(&io, infoTypeLen);
    WriteBuffer(&io, info, infoTypeLen);
    WriteInt32(&io, retCode);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc failed");
        return SOFTBUS_NETWORK_GET_SERVICE_IDENTITY_FAILED;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_TIME_SYNC_RESULT, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "SendRequest failed, ans=%{public}d", ans);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnPublishLNNResult(const char *pkgName, int32_t pid, int32_t publishId,
    int32_t reason)
{
    (void) pid;
    LNN_LOGI(LNN_EVENT, "enter");
    if (pkgName == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&io, publishId);
    WriteInt32(&io, reason);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc failed");
        return SOFTBUS_NETWORK_GET_SERVICE_IDENTITY_FAILED;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_PUBLISH_LNN_RESULT, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "SendRequest failed, ans=%{public}d", ans);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnRefreshLNNResult(const char *pkgName, int32_t pid, int32_t refreshId,
    int32_t reason)
{
    (void)pid;
    LNN_LOGI(LNN_EVENT, "enter");
    if (pkgName == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&io, refreshId);
    WriteInt32(&io, reason);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc failed");
        return SOFTBUS_NETWORK_GET_SERVICE_IDENTITY_FAILED;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_REFRESH_LNN_RESULT, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "SendRequest failed, ans=%{public}d", ans);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnRefreshDeviceFound(const char *pkgName, int32_t pid, const void *device,
    uint32_t deviceLen)
{
    (void)pid;
    LNN_LOGI(LNN_EVENT, "enter.");
    if (pkgName == NULL || device == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN_EX];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN_EX, 0);
    WriteUint32(&io, deviceLen);
    WriteBuffer(&io, device, deviceLen);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get svc failed");
        return SOFTBUS_NETWORK_GET_SERVICE_IDENTITY_FAILED;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_REFRESH_DEVICE_FOUND, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "SendRequest failed, ans=%{public}d", ans);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}