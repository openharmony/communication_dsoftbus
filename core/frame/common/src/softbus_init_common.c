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

#include "comm_log.h"
#include "softbus_init_common.h"

#ifdef __aarch64__
#define SOFTBUS_SERVER_PLUGIN_PATH_NAME "/system/lib64/libdsoftbus_server_plugin.z.so"
#else
#define SOFTBUS_SERVER_PLUGIN_PATH_NAME  "/system/lib/libdsoftbus_server_plugin.z.so"
#endif

#ifdef __aarch64__
#define SOFTBUS_CLIENT_PLUGIN_PATH_NAME "/system/lib64/platformsdk/libdsoftbus_client_plugin.z.so"
#else
#define SOFTBUS_CLIENT_PLUGIN_PATH_NAME "/system/lib/platformsdk/libdsoftbus_client_plugin.z.so"
#endif

#ifdef __aarch64__
#define SOFTBUS_SERVER_PATH_NAME "/system/lib64/libsoftbus_server.z.so"
#else
#define SOFTBUS_SERVER_PATH_NAME "/system/lib/libsoftbus_server.z.so"
#endif

#ifdef __aarch64__
#define SOFTBUS_CLIENT_PATH_NAME "/system/lib64/platformsdk/libsoftbus_client.z.so"
#else
#define SOFTBUS_CLIENT_PATH_NAME "/system/lib/platformsdk/libsoftbus_client.z.so"
#endif

bool g_softbusServerPluginLoaded = false;
bool g_softbusClientPluginLoaded = false;

void *g_soHandle[SOFTBUS_HANDLE_BUTT];
const char *g_soName[SOFTBUS_HANDLE_BUTT] = {
    SOFTBUS_SERVER_PLUGIN_PATH_NAME,
    SOFTBUS_CLIENT_PLUGIN_PATH_NAME,
    SOFTBUS_SERVER_PATH_NAME,
    SOFTBUS_CLIENT_PATH_NAME
};

bool SoftbusServerPluginLoadedFlagGet(void)
{
    return (g_soHandle[SOFTBUS_HANDLE_SERVER_PLUGIN] != NULL);
}

bool SoftbusClientPluginLoadedFlagGet(void)
{
    return (g_soHandle[SOFTBUS_HANDLE_CLIENT_PLGUIN] != NULL);
}

int32_t SoftBusDlopen(SoftBusHandleType type, void **dllHandle)
{
    if (type > SOFTBUS_HANDLE_BUTT || dllHandle == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_soHandle[type] != NULL) {
        *dllHandle = g_soHandle[type];
        return SOFTBUS_OK;
    }

    *dllHandle = dlopen(g_soName[type], RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL);
    if (*dllHandle == NULL) {
        COMM_LOGE(COMM_SVC, "dlopen %{public}s Load lib failed.", g_soName[type]);
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }

    g_soHandle[type] = *dllHandle;

    return SOFTBUS_OK;
}

int32_t SoftBusDlsym(const void *DllHandle, const char *funcName, void **funcHandle)
{
    if (DllHandle == NULL || funcName == NULL || funcHandle == NULL) {
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }

    *funcHandle = dlsym((void *)DllHandle, funcName);
    if (*funcHandle == NULL) {
        COMM_LOGE(COMM_SVC, "Load symbol %{public}s failed.", funcName);
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }

    return SOFTBUS_OK;
}

void SoftBusDlclose(SoftBusHandleType type)
{
    if (type > SOFTBUS_HANDLE_BUTT || g_soHandle[type] == NULL) {
        return;
    }

    dlclose((void *)g_soHandle[type]);
    g_soHandle[type] = NULL;
    return;
}

int32_t LnnCheckFuncPointer(void *func)
{
    if (func == NULL) {
        COMM_LOGE(COMM_TEST, "func not register.");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return SOFTBUS_OK;
}

int32_t ConnCheckFuncPointer(void *func)
{
    if (func == NULL) {
        COMM_LOGE(COMM_TEST, "func not register.");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return SOFTBUS_OK;
}

int32_t DiscCheckFuncPointer(void *func)
{
    if (func == NULL) {
        COMM_LOGE(COMM_TEST, "func not register.");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return SOFTBUS_OK;
}

int32_t TransCheckFuncPointer(void *func)
{
    if (func == NULL) {
        COMM_LOGE(COMM_TEST, "func not register.");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return SOFTBUS_OK;
}

int32_t AuthCheckFuncPointer(void *func)
{
    if (func == NULL) {
        COMM_LOGE(COMM_TEST, "func not register.");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return SOFTBUS_OK;
}

int32_t AdapterCheckFuncPointer(void *func)
{
    if (func == NULL) {
        COMM_LOGE(COMM_TEST, "func not register.");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return SOFTBUS_OK;
}