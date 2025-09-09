/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbus_conn_ipc.h"
#include "softbus_conn_general_connection.h"

#include "general_connection_client_proxy.h"
#include "conn_log.h"
#include "softbus_connection.h"

static void GeneralDataReceived(GeneralConnectionParam *info,
    uint32_t generalHandle, const uint8_t *data, uint32_t dataLen)
{
    ClientIpcOnDataReceived(info->pkgName, info->pid, generalHandle, data, dataLen);
}

static void GeneralConnectionDisconnected(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason)
{
    ClientIpcOnConnectionStateChange(info->pkgName, info->pid, generalHandle, CONNECTION_STATE_DISCONNECTED, reason);
}

static void GeneralAcceptConnect(GeneralConnectionParam *info, uint32_t generalHandle)
{
    ClientIpcOnAcceptConnect(info->pkgName, info->pid, info->name, generalHandle);
}

static void GeneralConnectFail(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason)
{
    ClientIpcOnConnectionStateChange(info->pkgName, info->pid, generalHandle,
        CONNECTION_STATE_CONNECTED_FAILED, reason);
}

static void GeneralConnectSuccess(GeneralConnectionParam *info, uint32_t generalHandle)
{
    ClientIpcOnConnectionStateChange(info->pkgName, info->pid, generalHandle, CONNECTION_STATE_CONNECTED_SUCCESS, 0);
}

GeneralConnectionListener g_baseListener = {
    .onConnectSuccess = GeneralConnectSuccess,
    .onConnectFailed = GeneralConnectFail,
    .onAcceptConnect = GeneralAcceptConnect,
    .onDataReceived = GeneralDataReceived,
    .onConnectionDisconnected = GeneralConnectionDisconnected,
};

void ClearGeneralConnection(const char *pkgName, int32_t pid)
{
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    if (manager == NULL) {
        COMM_LOGE(CONN_COMMON, "manager is null");
        return;
    }
    manager->cleanupGeneralConnection(pkgName, pid);
}

int32_t InitGeneralConnection(void)
{
    int32_t ret = InitGeneralConnectionManager();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(CONN_COMMON, "init general manager fail, err=%{public}d", ret);
        return SOFTBUS_NO_INIT;
    }

    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    if (manager == NULL) {
        COMM_LOGE(CONN_COMMON, "manager is null");
        return SOFTBUS_NO_INIT;
    }
    ret = manager->registerListener(&g_baseListener);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(CONN_COMMON, "init general manager fail, err=%{public}d", ret);
        return SOFTBUS_NO_INIT;
    }
    COMM_LOGI(CONN_COMMON, "init and refister listener success");
    return SOFTBUS_OK;
}