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

#include "general_client_connection.h"

#include <string.h>
#include "conn_log.h"
#include "general_connection_server_proxy.h"
#include "softbus_adapter_thread.h"
#include "softbus_client_stub_interface.h"
#include "softbus_connection.h"
#include "softbus_utils.h"
#include "softbus_client_frame_manager.h"

static IGeneralListener *g_connectionListener = NULL;
static SoftBusMutex g_connectionListenerLock;
const char *g_limitPkgName = "dms";

static bool IsValidListener(IGeneralListener *listener)
{
    if (listener == NULL || listener->OnAcceptConnect == NULL || listener->OnConnectionStateChange == NULL ||
        listener->OnDataReceived == NULL || listener->OnServiceDied == NULL) {
        CONN_LOGE(CONN_INIT, "listener is invalid");
        return false;
    }
    return true;
}

int32_t GeneralRegisterListener(IGeneralListener *listener)
{
    if (!IsValidListener(listener)) {
        CONN_LOGE(CONN_INIT, "listener is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexInit(&g_connectionListenerLock, NULL) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "mutex init failed");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SoftBusMutexLock(&g_connectionListenerLock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock failed");
        return ret;
    }
    g_connectionListener = listener;
    (void)SoftBusMutexUnlock(&g_connectionListenerLock);
    CONN_LOGI(CONN_INIT, "GeneralRegisterListener success");
    return SOFTBUS_OK;
}

int32_t GeneralUnregisterListener(void)
{
    if (g_connectionListener == NULL) {
        CONN_LOGW(CONN_INIT, "listener has not registered");
        return SOFTBUS_OK;
    }
    int32_t ret = SoftBusMutexLock(&g_connectionListenerLock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock failed");
        return ret;
    }
    g_connectionListener = NULL;
    (void)SoftBusMutexUnlock(&g_connectionListenerLock);
    (void)SoftBusMutexDestroy(&g_connectionListenerLock);
    CONN_LOGI(CONN_INIT, "GeneralUnregisterListener success");
    return SOFTBUS_OK;
}

static int32_t CheckNameIsValid(const char *pkgName, const char *name)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1)) {
        CONN_LOGE(CONN_COMMON, "invalid package name");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsValidString(name, SESSION_NAME_SIZE_MAX - 1)) {
        CONN_LOGE(CONN_COMMON, "invalid name");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(pkgName, g_limitPkgName) != 0) {
        CONN_LOGE(CONN_COMMON, "invalid package name");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t GeneralCreateServer(const char *pkgName, const char *name)
{
    int32_t ret = CheckNameIsValid(pkgName, name);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "invalid param");
        return ret;
    }
    ret = InitSoftBus(pkgName);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "register service failed");
        return ret;
    }
    ret = ServerIpcCreateServer(pkgName, name);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "create server failed");
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "create server success");
    return ret;
}

int32_t GeneralRemoveServer(const char *pkgName, const char *name)
{
    int32_t ret = CheckNameIsValid(pkgName, name);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "invalid param");
        return ret;
    }
    ret = ServerIpcRemoveServer(pkgName, name);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "remove server failed");
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "remove server success");
    return ret;
}

int32_t GeneralConnect(const char *pkgName, const char *name, const Address *address)
{
    int32_t ret = CheckNameIsValid(pkgName, name);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "invalid param");
        return ret;
    }
    if (address == NULL) {
        CONN_LOGE(CONN_COMMON, "address is null");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = InitSoftBus(pkgName);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "register service failed");
        return ret;
    }
    int32_t handle = ServerIpcConnect(pkgName, name, address);
    if (handle <= 0) {
        CONN_LOGE(CONN_COMMON, "connect failed, error=%{public}d", handle);
        return handle;
    }
    CONN_LOGI(CONN_COMMON, "connect success, handle=%{public}d", handle);
    return handle;
}

int32_t GeneralDisconnect(uint32_t handle)
{
    CONN_LOGI(CONN_COMMON, "sdk disconnect, handle=%{public}u", handle);
    if (handle <= 0) {
        CONN_LOGE(CONN_COMMON, "invalid handle");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ServerIpcDisconnect(handle);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "disconnect failed, ret=%{public}d", ret);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "disconnect success, handle=%{public}u", handle);
    return SOFTBUS_OK;
}

int32_t GeneralSend(uint32_t handle, const uint8_t *data, uint32_t len)
{
    CONN_LOGI(CONN_COMMON, "sdk send, handle=%{public}u, len=%{public}u", handle, len);
    if (handle <= 0) {
        CONN_LOGE(CONN_COMMON, "invalid handle");
        return SOFTBUS_INVALID_PARAM;
    }
    if (data == NULL) {
        CONN_LOGE(CONN_COMMON, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (len == 0 || len > GENERAL_SEND_DATA_MAX_LEN) {
        CONN_LOGE(CONN_COMMON, "len is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ServerIpcSend(handle, data, len);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "send failed");
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "send success, handle=%{public}u, len=%{public}u", handle, len);
    return ret;
}

int32_t GeneraConnGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len)
{
    CONN_LOGI(CONN_COMMON, "sdk get peer device id, handle=%{public}u", handle);
    if (handle <= 0) {
        CONN_LOGE(CONN_COMMON, "invalid handle");
        return SOFTBUS_INVALID_PARAM;
    }
    if (deviceId == NULL) {
        CONN_LOGE(CONN_COMMON, "deviceId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (len == 0 || len > BT_MAC_LEN) {
        CONN_LOGE(CONN_COMMON, "len is 0 or too long");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ServerIpcGetPeerDeviceId(handle, deviceId, len);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "get peer device id failed, ret=%{public}d", ret);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "get peer device id success, handle=%{public}u, deviceId=%{public}s", handle, deviceId);
    return SOFTBUS_OK;
}

int32_t ConnectionStateChange(uint32_t handle, int32_t state, int32_t reason)
{
    CONN_LOGI(CONN_COMMON, "sdk connection state change, handle=%{public}u, state=%{public}d, reason=%{public}d",
        handle, state, reason);
    if (SoftBusMutexLock(&g_connectionListenerLock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_connectionListener == NULL || g_connectionListener->OnConnectionStateChange == NULL) {
        (void)SoftBusMutexUnlock(&g_connectionListenerLock);
        CONN_LOGE(CONN_COMMON, "notify connection state change failed, listener is null.");
        return SOFTBUS_NO_INIT;
    }
    int32_t ret = g_connectionListener->OnConnectionStateChange(handle, state, reason);
    (void)SoftBusMutexUnlock(&g_connectionListenerLock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "notify connection state change failed, ret=%{public}d", ret);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "notify connection state change success");
    return SOFTBUS_OK;
}

int32_t AcceptConnect(const char *name, uint32_t handle)
{
    CONN_LOGI(CONN_COMMON, "sdk accept connect, handle=%{public}u", handle);
    if (SoftBusMutexLock(&g_connectionListenerLock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_connectionListener == NULL || g_connectionListener->OnAcceptConnect == NULL) {
        (void)SoftBusMutexUnlock(&g_connectionListenerLock);
        CONN_LOGE(CONN_COMMON, "notify accept connect failed, listener is null.");
        return SOFTBUS_NO_INIT;
    }
    int32_t ret = g_connectionListener->OnAcceptConnect(name, handle);
    (void)SoftBusMutexUnlock(&g_connectionListenerLock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "accept connect failed, ret=%{public}d", ret);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "notify accept connect success");
    return SOFTBUS_OK;
}

void DataReceived(uint32_t handle, const uint8_t *data, uint32_t len)
{
    CONN_LOGI(CONN_COMMON, "sdk data received, handle=%{public}u, len=%{public}u", handle, len);
    if (SoftBusMutexLock(&g_connectionListenerLock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock failed");
        return;
    }
    if (g_connectionListener == NULL || g_connectionListener->OnDataReceived == NULL) {
        (void)SoftBusMutexUnlock(&g_connectionListenerLock);
        CONN_LOGE(CONN_COMMON, "notify data received failed, listener is null.");
        return;
    }
    g_connectionListener->OnDataReceived(handle, data, len);
    (void)SoftBusMutexUnlock(&g_connectionListenerLock);
    CONN_LOGI(CONN_COMMON, "notify data received success");
}

void ConnectionDeathNotify(void)
{
    CONN_LOGI(CONN_COMMON, "connection death notify.");
    if (g_connectionListener == NULL) {
        CONN_LOGI(CONN_COMMON, "listener has not registered, no need to notify.");
        return;
    }
    if (SoftBusMutexLock(&g_connectionListenerLock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock failed");
        return;
    }
    if (g_connectionListener->OnConnectionStateChange != NULL) {
        (void)g_connectionListener->OnConnectionStateChange(0, CONNECTION_STATE_DISCONNECTED, SOFTBUS_CONN_FAIL);
    }
    if (g_connectionListener->OnServiceDied != NULL) {
        g_connectionListener->OnServiceDied();
    }
    (void)SoftBusMutexUnlock(&g_connectionListenerLock);
    CONN_LOGI(CONN_COMMON, "connection death notify success.");
}