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

bool g_softbusServerPluginLoaded = false;
bool g_softbusClientPluginLoaded = false;

bool SoftbusServerPluginLoadedFlagGet(void)
{
    return g_softbusServerPluginLoaded;
}

bool SoftbusClientPluginLoadedFlagGet(void)
{
    return g_softbusClientPluginLoaded;
}

void SoftbusServerPluginLoadedFlagSet(bool soLoadFlag)
{
    g_softbusServerPluginLoaded = soLoadFlag;
}

void SoftbusClientPluginLoadedFlagSet(bool soLoadFlag)
{
    g_softbusClientPluginLoaded = soLoadFlag;
}


/**
 * @brief Opens the specified dynamic link library.
 *
 * @param DllName Indicates the unique dynamic link library name, which cannot be <b>NULL</b>.
 * @param DllHandle Indicates the pointer to the DLL handle to get, which cannot be <b>NULL</b>.
 *
 * @return Returns <b>SOFTBUS_NOT_IMPLEMENT</b> if dlopen can not fount <b>DllName</b>.
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t SoftBusDlopen(const char *DllName, void **DllHandle)
{
    // *DllHandle = dlopen(DllName, RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL);
    *DllHandle = dlopen(DllName, RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL);
    if (DllHandle == NULL) {
        COMM_LOGE(COMM_SVC, "dlopen %s Load lib failed.", DllName);
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }

    return SOFTBUS_OK;
}

/**
 * @brief Dynamically resolve symbols (names of functions or global variables).
 *
 * @param DllHandle Indicates the unique dynamic link library handle, which cannot be <b>NULL</b>.
 * @param funcName Indicates the function or global variable name, which cannot be <b>NULL</b>.
 * @param funcHandle Indicates the pointer to the function pointer or global variables to get, which cannot be <b>NULL</b>.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the operation is successful; returns an error code otherwise.
 * @since 2.0
 * @version 2.0
 */
int32_t SoftBusDlsym(const void *DllHandle, const char *funcName, void **funcHandle)
{
    *funcHandle = dlsym((void *)DllHandle, funcName);
    if (funcHandle == NULL) {
        COMM_LOGE(COMM_SVC, "Load symbol %s failed.", funcName);
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }

    return SOFTBUS_OK;
}

/**
 * @brief Dynamically resolve symbols (names of functions or global variables).
 *
 * @param DllHandle Indicates the unique dynamic link library handle, which cannot be <b>NULL</b>.
 *
 * @return Returns no value.
 * @since 2.0
 * @version 2.0
 */
void SoftBusDlclose(const void *DllHandle)
{
    dlclose((void *)DllHandle);
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