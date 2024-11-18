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

#include "softbus_adapter_bt_common.h"

#include "softbus_error_code.h"

int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    (void)listener;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int SoftBusRemoveBtStateListener(int listenerId)
{
    return SOFTBUS_OK;
}

int SoftBusEnableBt(void)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int SoftBusDisableBt(void)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int SoftBusGetBrState(void)
{
    return BR_DISABLE;
}

int SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return SOFTBUS_OK;
}

int SoftBusGetBtName(unsigned char *name, unsigned int *len)
{
    (void)name;
    (void)len;
    return SOFTBUS_OK;
}

int SoftBusSetBtName(const char *name)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int SoftBusBtInit(void)
{
    return SOFTBUS_OK;
}