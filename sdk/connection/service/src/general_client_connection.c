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
const char *g_limitPkgName = "ohos.distributedschedule.dms";

static bool IsValidListener(IGeneralListener *listener)
{
    if (listener == NULL || listener->OnAcceptConnect == NULL || listener->OnConnectionStateChange == NULL ||
        listener->OnDataReceived == NULL || listener->OnServiceDied == NULL || listener->OnServiceStopped == NULL) {
        CONN_LOGE(CONN_INIT, "invalid listener");
        return false;
    }
    return true;
}

static IGeneralListener *GetConnectionListener(void)
{
    if (SoftBusMutexLock(&g_connectionListenerLock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock fail");
        return NULL;
    }
    IGeneralListener *listener = g_connectionListener;
    (void)SoftBusMutexUnlock(&g_connectionListenerLock);
    return listener;
}

int32_t GeneralRegisterListener(IGeneralListener *listener)
{
    if (!IsValidListener(listener)) {
        CONN_LOGE(CONN_INIT, "invalid listener");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexInit(&g_connectionListenerLock, NULL) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SoftBusMutexLock(&g_connectionListenerLock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock fail");
        SoftBusMutexDestroy(&g_connectionListenerLock);
        return ret;
    }
    g_connectionListener = listener;
    (void)SoftBusMutexUnlock(&g_connectionListenerLock);
    CONN_LOGI(CONN_INIT, "GeneralRegisterListener succ");
    return SOFTBUS_OK;
}

int32_t GeneralUnregisterListener(void)
{
    int32_t ret = SoftBusMutexLock(&g_connectionListenerLock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock fail");
        return ret;
    }
    if (g_connectionListener == NULL) {
        CONN_LOGW(CONN_INIT, "listener not registered");
        (void)SoftBusMutexUnlock(&g_connectionListenerLock);
        (void)SoftBusMutexDestroy(&g_connectionListenerLock);
        return SOFTBUS_OK;
    }
    g_connectionListener = NULL;
    (void)SoftBusMutexUnlock(&g_connectionListenerLock);
    (void)SoftBusMutexDestroy(&g_connectionListenerLock);
    CONN_LOGI(CONN_INIT, "GeneralUnregisterListener succ");
    return SOFTBUS_OK;
}

static int32_t CheckNameIsValid(const char *pkgName, const char *name)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1)) {
        CONN_LOGE(CONN_COMMON, "invalid pkg name");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsValidString(name, SESSION_NAME_SIZE_MAX - 1)) {
        CONN_LOGE(CONN_COMMON, "invalid name");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(pkgName, g_limitPkgName) != 0) {
        CONN_LOGE(CONN_COMMON, "invalid pkg name");
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
        CONN_LOGE(CONN_COMMON, "register service fail");
        return ret;
    }
    ret = ServerIpcCreateServer(pkgName, name);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "create server fail");
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "create server succ");
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
        CONN_LOGE(CONN_COMMON, "remove server fail");
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "remove server succ");
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
        CONN_LOGE(CONN_COMMON, "register service fail");
        return ret;
    }
    int32_t handle = ServerIpcConnect(pkgName, name, address);
    if (handle <= 0) {
        CONN_LOGE(CONN_COMMON, "connect fail, error=%{public}d", handle);
        return handle;
    }
    CONN_LOGI(CONN_COMMON, "connect succ, handle=%{public}d", handle);
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
        CONN_LOGE(CONN_COMMON, "disconnect fail, ret=%{public}d", ret);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "disconnect succ, handle=%{public}u", handle);
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
        CONN_LOGE(CONN_COMMON, "invalid len");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ServerIpcSend(handle, data, len);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "send fail");
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "send succ, handle=%{public}u, len=%{public}u", handle, len);
    return ret;
}

int32_t GeneralGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len)
{
    CONN_LOGI(CONN_COMMON, "sdk get device id, handle=%{public}u", handle);
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
        CONN_LOGE(CONN_COMMON, "get device id fail, ret=%{public}d", ret);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "get device id succ, handle=%{public}u", handle);
    return SOFTBUS_OK;
}

int32_t ConnectionStateChange(uint32_t handle, int32_t state, int32_t reason)
{
    CONN_LOGI(CONN_COMMON, "sdk connection state change, handle=%{public}u, state=%{public}d, reason=%{public}d",
        handle, state, reason);
    IGeneralListener *listener = GetConnectionListener();
    if (listener == NULL || listener->OnConnectionStateChange == NULL) {
        CONN_LOGE(CONN_COMMON, "notify connection state change fail, listener is null.");
        return SOFTBUS_NO_INIT;
    }
    int32_t ret = listener->OnConnectionStateChange(handle, state, reason);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "notify connection state change fail, ret=%{public}d", ret);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "notify connection state change succ");
    return SOFTBUS_OK;
}

int32_t AcceptConnect(const char *name, uint32_t handle)
{
    CONN_LOGI(CONN_COMMON, "sdk accept connect, handle=%{public}u", handle);
    IGeneralListener *listener = GetConnectionListener();
    if (listener == NULL || listener->OnAcceptConnect == NULL) {
        CONN_LOGE(CONN_COMMON, "notify accept connect fail, listener is null");
        return SOFTBUS_NO_INIT;
    }
    int32_t ret = listener->OnAcceptConnect(name, handle);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "accept connect fail, ret=%{public}d", ret);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "notify accept connect succ");
    return SOFTBUS_OK;
}

void DataReceived(uint32_t handle, const uint8_t *data, uint32_t len)
{
    CONN_CHECK_AND_RETURN_LOGE(len > 0 && len <= GENERAL_SEND_DATA_MAX_LEN, CONN_COMMON, "len=%{public}u", len);
    CONN_LOGI(CONN_COMMON, "sdk data received, handle=%{public}u, len=%{public}u", handle, len);
    IGeneralListener *listener = GetConnectionListener();
    if (listener == NULL || listener->OnDataReceived == NULL) {
        CONN_LOGE(CONN_COMMON, "notify data received fail, listener is null.");
        return;
    }
    listener->OnDataReceived(handle, data, len);
    CONN_LOGI(CONN_COMMON, "notify data received succ");
}

void ConnectionDeathNotify(void)
{
    CONN_LOGI(CONN_COMMON, "connection death notify");
    IGeneralListener *listener = GetConnectionListener();
    if (listener == NULL) {
        CONN_LOGE(CONN_COMMON, "connection death notify fail, listener is null");
        return;
    }
    if (listener->OnConnectionStateChange != NULL) {
        (void)listener->OnConnectionStateChange(0, CONNECTION_STATE_DISCONNECTED, SOFTBUS_CONN_FAIL);
    }
    if (listener->OnServiceDied != NULL) {
        listener->OnServiceDied();
    }
    CONN_LOGI(CONN_COMMON, "connection death notify succ");
}

int32_t ServerStopped(const char *name)
{
    CONN_LOGI(CONN_COMMON, "connect server stopped");
    IGeneralListener *listener = GetConnectionListener();
    if (listener == NULL || listener->OnServiceStopped == NULL) {
        CONN_LOGE(CONN_COMMON, "notify server stopped fail, listener is null");
        return SOFTBUS_NO_INIT;
    }
    if (name != NULL) {
        listener->OnServiceStopped(name);
    }
    CONN_LOGI(CONN_COMMON, "connect server stopped succ");
    return SOFTBUS_OK;
}