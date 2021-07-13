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

#include "liteipc_adapter.h"
#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

static int32_t GetSvcIdentityByPkgName(const char *pkgName, SvcIdentity *svc)
{
    struct CommonScvId svcId = {0};
    if (SERVER_GetIdentityByPkgName(pkgName, &svcId) != SOFTBUS_OK) {
        LOG_ERR("bus center callback failed.");
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

static int32_t GetAllClientIdentity(SvcIdentity *svc, int num)
{
    if (svc == NULL || num == 0) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    struct CommonScvId *svcId = (struct CommonScvId *)SoftBusMalloc(sizeof(struct CommonScvId) * num);
    if (svcId == NULL) {
        LOG_ERR("malloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(svcId, sizeof(struct CommonScvId) * num, 0, sizeof(struct CommonScvId) * num);
    if (SERVER_GetAllClientIdentity(svcId, num) != SOFTBUS_OK) {
        LOG_ERR("bus center callback failed.");
        return SOFTBUS_ERR;
    }
    for (int i = 0; i < num; i++) {
        svc[i].handle = svcId[i].handle;
        svc[i].token = svcId[i].token;
        svc[i].cookie = svcId[i].cookie;
#ifdef __LINUX__
        svc[i].ipcContext = svcId[i].ipcCtx;
#endif
    }
    SoftBusFree(svcId);
    return SOFTBUS_OK;
}

int32_t ClientOnJoinLNNResult(const char *pkgName, void *addr, uint32_t addrTypeLen,
    const char *networkId, int32_t retCode)
{
    LOG_INFO("OnJoinLNNResult ipc server push.");
    if (pkgName == NULL || addr == NULL || (retCode == 0 && networkId == NULL)) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushFlatObj(&io, addr, addrTypeLen);
    IpcIoPushInt32(&io, retCode);
    if (retCode == 0) {
        IpcIoPushString(&io, networkId);
    }
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        LOG_ERR("OnJoinLNNResult callback get svc failed.");
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_ON_JOIN_RESULT, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        LOG_ERR("OnJoinLNNResult callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnLeaveLNNResult(const char *pkgName, const char *networkId, int retCode)
{
    LOG_INFO("OnLeaveLNNResult callback ipc server push.");
    if (networkId == NULL) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushString(&io, networkId);
    IpcIoPushInt32(&io, retCode);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        LOG_ERR("OnLeaveLNNResult callback get svc failed.");
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_ON_LEAVE_RESULT, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        LOG_ERR("OnLeaveLNNResult callback SendRequest failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    LOG_INFO("ClinetOnNodeOnlineStateChanged callback ipc server push.");
    if (info == NULL) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushBool(&io, isOnline);
    IpcIoPushFlatObj(&io, info, infoTypeLen);
    int num;
    int i;
    if (SERVER_GetClientInfoNodeNum(&num) != SOFTBUS_OK) {
        LOG_ERR("ClinetOnNodeOnlineStateChanged callback get svc num failed.");
        return SOFTBUS_ERR;
    }
    if (num == 0) {
        LOG_ERR("ClinetOnNodeOnlineStateChanged callback svc num NULL.");
        return SOFTBUS_ERR;
    }
    SvcIdentity *svc = (SvcIdentity *)SoftBusCalloc(sizeof(SvcIdentity) * num);
    if (svc == NULL) {
        LOG_ERR("malloc failed");
        return SOFTBUS_ERR;
    }
    if (GetAllClientIdentity(svc, num) != SOFTBUS_OK) {
        LOG_ERR("ClinetOnNodeBasicInfoChanged callback get svc num failed.");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < num; i++) {
        int32_t ans = SendRequest(NULL, svc[i], CLIENT_ON_NODE_ONLINE_STATE_CHANGED, &io, NULL,
            LITEIPC_FLAG_ONEWAY, NULL);
        if (ans != SOFTBUS_OK) {
            LOG_ERR("ClinetOnNodeOnlineStateChanged callback SendRequest failed.");
            return SOFTBUS_ERR;
        }
    }
    SoftBusFree(svc);
    return SOFTBUS_OK;
}

int32_t ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    LOG_INFO("ClinetOnNodeBasicInfoChanged callback ipc server push.");
    if (info == NULL) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushInt32(&io, type);
    IpcIoPushFlatObj(&io, info, infoTypeLen);
    int num;
    int i;
    if (SERVER_GetClientInfoNodeNum(&num) != SOFTBUS_OK) {
        LOG_ERR("ClinetOnNodeBasicInfoChanged callback get svc num failed.");
        return SOFTBUS_ERR;
    }
    if (num == 0) {
        LOG_ERR("ClinetOnNodeBasicInfoChanged callback svc num NULL.");
        return SOFTBUS_ERR;
    }
    SvcIdentity *svc = (SvcIdentity *)SoftBusCalloc(sizeof(SvcIdentity) * num);
    if (svc == NULL) {
        LOG_ERR("malloc failed");
        return SOFTBUS_ERR;
    }
    if (GetAllClientIdentity(svc, num) != SOFTBUS_OK) {
        LOG_ERR("ClinetOnNodeBasicInfoChanged callback get svc num failed.");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < num; i++) {
        int32_t ans = SendRequest(NULL, svc[i], CLIENT_ON_NODE_BASIC_INFO_CHANGED, &io, NULL,
            LITEIPC_FLAG_ONEWAY, NULL);
        if (ans != SOFTBUS_OK) {
            LOG_ERR("ClinetOnNodeBasicInfoChanged callback SendRequest failed.");
            return SOFTBUS_ERR;
        }
    }
    SoftBusFree(svc);
    return SOFTBUS_OK;
}