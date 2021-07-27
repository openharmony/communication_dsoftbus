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

#include "liteipc_adapter.h"
#include "serializer.h"
#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

static int32_t GetSvcIdentityByPkgName(const char *pkgName, SvcIdentity *svc)
{
    struct CommonScvId svcId = {0};
    if (SERVER_GetIdentityByPkgName(pkgName, &svcId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ondevice found callback failed.");
        return SOFTBUS_ERR;
    }
    svc->handle = svcId.handle;
    svc->token = svcId.token;
    svc->cookie = svcId.cookie;
#ifdef __LINUX__
    svc->ipcContext = svcId.ipcCtx;
#endif
    return SOFTBUS_OK;
}

int32_t ClientIpcOnDeviceFound(const char *pkgName, const DeviceInfo *device)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ondevice found ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN_EX] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN_EX, 0);
    IpcIoPushFlatObj(&io, (const void*)device, sizeof(DeviceInfo));
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ondevice found callback get svc failed.");
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_DISCOVERY_DEVICE_FOUND, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ondevice found callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcOnDiscoverFailed(const char *pkgName, int subscribeId, int failReason)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "on discovery failed callback ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushInt32(&io, subscribeId);
    IpcIoPushInt32(&io, failReason);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "on discovery failed callback get svc failed.");
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_DISCOVERY_FAIL, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "on discovery failed callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcDiscoverySuccess(const char *pkgName, int subscribeId)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "on discovery success callback ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushInt32(&io, subscribeId);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "on discovery success callback get svc failed.");
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_DISCOVERY_SUCC, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "on discovery success callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishSuccess(const char *pkgName, int publishId)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "on publish success callback ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushInt32(&io, publishId);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "on publish success callback get svc failed.");
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_PUBLISH_SUCC, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "on publish success callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishFail(const char *pkgName, int publishId, int reason)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "on publish failed ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushInt32(&io, publishId);
    IpcIoPushInt32(&io, reason);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "on publish failed callback get svc failed.");
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_PUBLISH_FAIL, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "on publish failed callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
