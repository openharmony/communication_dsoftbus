/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "far_field_proxy_adapter.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_init_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "securec.h"
#include <dlfcn.h>
#include <stddef.h>
#include <string.h>

typedef int32_t (*FarFieldInitProxyFunc)(void);
typedef int32_t (*FarFieldDeinitProxyFunc)(void);
typedef bool (*FarFieldIsDeviceSupportFunc)(const P2PDeviceInfo *);
typedef int32_t (*FarFieldRegisterCallbackFunc)(const FarFieldCallbackSt *);
typedef int32_t (*FarFieldOpenP2PFunc)(const P2PDeviceInfo *);
typedef int32_t (*FarFieldCloseP2PFunc)(const P2PDeviceInfo *);
typedef P2PState (*FarFieldGetP2PStateFunc)(const P2PDeviceInfo *);
typedef int32_t (*FarFieldSendMsgFunc)(const P2PDeviceInfo *, const uint8_t *, uint32_t);
typedef int32_t (*FarFieldRefreshFunc)(const P2PDeviceInfo *);

typedef struct {
    void *soHandle;
    bool isInitialized;
    bool isSoLoad;
    int32_t refCount;
    FarFieldInitProxyFunc initProxy;
    FarFieldDeinitProxyFunc deinitProxy;
    FarFieldIsDeviceSupportFunc isDeviceSupport;
    FarFieldRegisterCallbackFunc registerCallback;
    FarFieldOpenP2PFunc openP2P;
    FarFieldCloseP2PFunc closeP2P;
    FarFieldGetP2PStateFunc getP2PState;
    FarFieldSendMsgFunc sendMsg;
    FarFieldRefreshFunc refresh;
} FarFieldAdapterContext;

static FarFieldAdapterContext g_adapterContext = {
    .soHandle = NULL,
    .isInitialized = false,
    .isSoLoad = false,
    .refCount = 0,
};

static FarFieldCallbackSt *g_farFieldCallback = NULL;

static SoftBusMutex g_adapterMutex;

static int32_t LoadFarFieldSymbols(void)
{
    g_adapterContext.initProxy = (FarFieldInitProxyFunc)dlsym(g_adapterContext.soHandle, "FarFieldInitProxy");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_adapterContext.initProxy != NULL, FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND, CONN_PROXY,
        "Failed to load FarFieldInitProxy symbol");

    g_adapterContext.deinitProxy = (FarFieldDeinitProxyFunc)dlsym(g_adapterContext.soHandle, "FarFieldDeinitProxy");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_adapterContext.deinitProxy != NULL, FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND, CONN_PROXY,
        "Failed to load FarFieldDeinitProxy symbol");

    g_adapterContext.isDeviceSupport = (FarFieldIsDeviceSupportFunc)dlsym(g_adapterContext.soHandle,
        "FarFieldIsDeviceSupport");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_adapterContext.isDeviceSupport != NULL, FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND,
        CONN_PROXY, "Failed to load FarFieldIsDeviceSupport symbol");

    g_adapterContext.registerCallback = (FarFieldRegisterCallbackFunc)dlsym(g_adapterContext.soHandle,
        "FarFieldRegisterCallback");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_adapterContext.registerCallback != NULL, FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND,
        CONN_PROXY, "Failed to load FarFieldRegisterCallback symbol");

    g_adapterContext.openP2P = (FarFieldOpenP2PFunc)dlsym(g_adapterContext.soHandle, "FarFieldOpenP2P");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_adapterContext.openP2P != NULL, FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND, CONN_PROXY,
        "Failed to load FarFieldOpenP2P symbol");

    g_adapterContext.closeP2P = (FarFieldCloseP2PFunc)dlsym(g_adapterContext.soHandle, "FarFieldCloseP2P");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_adapterContext.closeP2P != NULL, FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND, CONN_PROXY,
        "Failed to load FarFieldCloseP2P symbol");

    g_adapterContext.getP2PState = (FarFieldGetP2PStateFunc)dlsym(g_adapterContext.soHandle, "FarFieldGetP2PState");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_adapterContext.getP2PState != NULL, FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND, CONN_PROXY,
        "Failed to load FarFieldGetP2PState symbol");

    g_adapterContext.sendMsg = (FarFieldSendMsgFunc)dlsym(g_adapterContext.soHandle, "FarFieldSendMsg");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_adapterContext.sendMsg != NULL, FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND, CONN_PROXY,
        "Failed to load FarFieldSendMsg symbol");

    g_adapterContext.refresh = (FarFieldRefreshFunc)dlsym(g_adapterContext.soHandle, "FarFieldRefresh");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_adapterContext.refresh != NULL, FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND, CONN_PROXY,
        "Failed to load FarFieldRefresh symbol");

    CONN_LOGI(CONN_PROXY, "All symbols loaded successfully");
    return SOFTBUS_OK;
}

static int32_t LoadFarFieldSo(void)
{
    if (g_adapterContext.isSoLoad) {
        CONN_LOGW(CONN_PROXY, "Adapter already initialized");
        g_adapterContext.refCount++;
        return SOFTBUS_OK;
    }

    int32_t ret = SoftBusDlopen(SOFTBUS_HANDLE_FAR_FIELD, &g_adapterContext.soHandle);
    if (ret != SOFTBUS_OK || g_adapterContext.soHandle == NULL) {
        CONN_LOGE(CONN_PROXY, "Failed to load far_field_proxy_manager.so, ret=%{public}d", ret);
        return ret;
    }
    ret = LoadFarFieldSymbols();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Failed to load symbols, ret=%{public}d", ret);
        dlclose(g_adapterContext.soHandle);
        g_adapterContext.soHandle = NULL;
        (void)memset_s(&g_adapterContext, sizeof(g_adapterContext), 0, sizeof(g_adapterContext));
        return ret;
    }
    g_adapterContext.isSoLoad = true;
    g_adapterContext.refCount = 1;
    return SOFTBUS_OK;
}

static void UnloadFarFieldSo(void)
{
    if (!g_adapterContext.isSoLoad) {
        return;
    }
    g_adapterContext.refCount--;
    CONN_LOGI(CONN_PROXY, "so refCount=%{public}d", g_adapterContext.refCount);
    if (g_adapterContext.refCount > 0) {
        return;
    }
    if (g_adapterContext.deinitProxy != NULL) {
        g_adapterContext.deinitProxy();
        g_adapterContext.deinitProxy = NULL;
        g_adapterContext.isInitialized = false;
    }

    if (g_adapterContext.soHandle != NULL) {
        dlclose(g_adapterContext.soHandle);
        g_adapterContext.soHandle = NULL;
    }
    (void)memset_s(&g_adapterContext, sizeof(g_adapterContext), 0, sizeof(g_adapterContext));
    g_adapterContext.isSoLoad = false;
    return;
}

static int32_t ReferenceSoRefCnt(void)
{
    int32_t ret = SoftBusMutexLock(&g_adapterMutex);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_PROXY, "LOCK fail");
    if (!g_adapterContext.isInitialized) {
        SoftBusMutexUnlock(&g_adapterMutex);
        return FAR_FIELD_ADAPTER_NOT_INITIALIZED;
    }
    g_adapterContext.refCount++;
    CONN_LOGI(CONN_PROXY, "so refCount=%{public}d", g_adapterContext.refCount);
    SoftBusMutexUnlock(&g_adapterMutex);
    return SOFTBUS_OK;
}

static void DeferenceSoRefCnt(void)
{
    int32_t ret = SoftBusMutexLock(&g_adapterMutex);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY, "LOCK fail");
    if (!g_adapterContext.isInitialized) {
        SoftBusMutexUnlock(&g_adapterMutex);
        return;
    }
    UnloadFarFieldSo();
    SoftBusMutexUnlock(&g_adapterMutex);
}

int32_t FarFieldAdapterInit(void)
{
    int32_t ret = SoftBusMutexLock(&g_adapterMutex);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_PROXY, "LOCK fail");

    ret = LoadFarFieldSo();
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_adapterMutex);
        CONN_LOGE(CONN_PROXY, "load so err=%{public}d", ret);
        return ret;
    }

    if (g_adapterContext.isInitialized) {
        CONN_LOGI(CONN_PROXY, "Already initialized, just increment refCount");
        SoftBusMutexUnlock(&g_adapterMutex);
        return FAR_FIELD_ADAPTER_ALREADY_INITIALIZED;
    }
    ret = g_adapterContext.registerCallback(g_farFieldCallback);
    if (ret != 0) {
        CONN_LOGE(CONN_PROXY, "registerCallback failed");
        UnloadFarFieldSo();
        SoftBusMutexUnlock(&g_adapterMutex);
        return FAR_FIELD_ADAPTER_ERROR;
    }
    if (g_adapterContext.initProxy() != 0) {
        CONN_LOGE(CONN_PROXY, "FarFieldInitProxy failed");
        UnloadFarFieldSo();
        SoftBusMutexUnlock(&g_adapterMutex);
        return FAR_FIELD_ADAPTER_ERROR;
    }
    g_adapterContext.isInitialized = true;
    CONN_LOGI(CONN_PROXY, "FarField adapter initialized successfully");
    SoftBusMutexUnlock(&g_adapterMutex);
    return SOFTBUS_OK;
}

void FarFieldAdapterDeinit(void)
{
    int32_t ret = SoftBusMutexLock(&g_adapterMutex);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY, "LOCK fail");
    UnloadFarFieldSo();
    SoftBusMutexUnlock(&g_adapterMutex);
}

bool FarFieldAdapterIsDeviceSupport(const P2PDeviceInfo *device)
{
    int32_t ret = SoftBusMutexLock(&g_adapterMutex);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false, CONN_PROXY, "LOCK fail");
    ret = LoadFarFieldSo();
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_adapterMutex);
        CONN_LOGE(CONN_PROXY, "load so err=%{public}d", ret);
        return false;
    }

    bool isSupport = g_adapterContext.isDeviceSupport(device);
    UnloadFarFieldSo();
    SoftBusMutexUnlock(&g_adapterMutex);
    return isSupport;
}

int32_t FarFieldAdapterRegisterCallback(const FarFieldCallbackSt *callback)
{
    if (callback == NULL) {
        CONN_LOGE(CONN_PROXY, "Invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ReferenceSoRefCnt();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Adapter not initialized");
        return FAR_FIELD_ADAPTER_NOT_INITIALIZED;
    }

    ret = g_adapterContext.registerCallback(callback);
    DeferenceSoRefCnt();
    return ret;
}

int32_t FarFieldAdapterOpenP2P(const P2PDeviceInfo *device)
{
    if (device == NULL) {
        CONN_LOGE(CONN_PROXY, "Invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ReferenceSoRefCnt();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Adapter not initialized");
        return FAR_FIELD_ADAPTER_NOT_INITIALIZED;
    }

    ret = g_adapterContext.openP2P(device);
    DeferenceSoRefCnt();
    return ret;
}

int32_t FarFieldAdapterCloseP2P(const P2PDeviceInfo *device)
{
    if (device == NULL) {
        CONN_LOGE(CONN_PROXY, "Invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ReferenceSoRefCnt();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Adapter not initialized");
        return FAR_FIELD_ADAPTER_NOT_INITIALIZED;
    }

    ret = g_adapterContext.closeP2P(device);
    DeferenceSoRefCnt();
    return ret;
}

P2PState FarFieldAdapterGetP2PState(const P2PDeviceInfo *device)
{
    if (device == NULL) {
        CONN_LOGE(CONN_PROXY, "Invalid params");
        return P2P_STATE_INVALID;
    }
    int32_t ret = ReferenceSoRefCnt();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Adapter not initialized");
        return P2P_STATE_INVALID;
    }

    P2PState state = g_adapterContext.getP2PState(device);
    DeferenceSoRefCnt();
    return state;
}

int32_t FarFieldAdapterSendMsg(const P2PDeviceInfo *device, const uint8_t *data, uint32_t len)
{
    if (device == NULL || data == NULL || len == 0) {
        CONN_LOGE(CONN_PROXY, "Invalid params");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = ReferenceSoRefCnt();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Adapter not initialized");
        return FAR_FIELD_ADAPTER_NOT_INITIALIZED;
    }

    ret = g_adapterContext.sendMsg(device, data, len);
    DeferenceSoRefCnt();
    return ret;
}

int32_t FarFieldAdapterRefresh(const P2PDeviceInfo *device)
{
    if (device == NULL) {
        CONN_LOGE(CONN_PROXY, "Invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ReferenceSoRefCnt();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Adapter not initialized");
        return FAR_FIELD_ADAPTER_NOT_INITIALIZED;
    }

    ret = g_adapterContext.refresh(device);
    DeferenceSoRefCnt();
    return ret;
}

int32_t FarFieldAdapterManagerInit(const FarFieldCallbackSt *callback)
{
    int32_t ret = SoftBusMutexInit(&g_adapterMutex, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_PROXY,
        "Failed to init adapter manager mutex");
    g_farFieldCallback = callback;
    return SOFTBUS_OK;
}

void FarFieldAdapterManagerDeinit(void)
{
    SoftBusMutexDestroy(&g_adapterMutex);
}
