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

#include <stdbool.h>

#include "ohos_bt_def.h"
#include "ohos_bt_gap.h"
#include "ohos_bt_gatt.h"

#include "securec.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define STATE_LISTENER_MAX_NUM 2

typedef struct {
    bool isUsed;
    SoftBusBtStateListener *listener;
} StateListener;

static int ConvertBtState(int state)
{
    switch (state) {
        case OHOS_GAP_STATE_TURNING_ON:
            return SOFTBUS_BT_STATE_TURNING_ON;
        case OHOS_GAP_STATE_TURN_ON:
            return SOFTBUS_BT_STATE_TURN_ON;
        case OHOS_GAP_STATE_TURNING_OFF:
            return SOFTBUS_BT_STATE_TURNING_OFF;
        case OHOS_GAP_STATE_TURN_OFF:
            return SOFTBUS_BT_STATE_TURN_OFF;
        default:
            return -1;
    }
}

static StateListener g_stateListener[STATE_LISTENER_MAX_NUM];
static bool g_isRegCb = false;

static void WrapperStateChangeCallback(const int transport, const int status)
{
    (void)transport;
    LOG_INFO("WrapperStateChangeCallback");
    int listenerId;
    int st = ConvertBtState((BtStatus)status);
    for (listenerId = 0; listenerId < STATE_LISTENER_MAX_NUM; listenerId++) {
        if (g_stateListener[listenerId].isUsed &&
            g_stateListener[listenerId].listener != NULL &&
            g_stateListener[listenerId].listener->OnBtStateChanged != NULL) {
            g_stateListener[listenerId].listener->OnBtStateChanged(listenerId, st);
        }
    }
}

static BtGapCallBacks g_softbusGapCb = {
    .stateChangeCallback = WrapperStateChangeCallback
};

static int RegisterListenerCallback(void)
{
    if (g_isRegCb) {
        return SOFTBUS_OK;
    }
    if (GapRegisterCallbacks(&g_softbusGapCb) != OHOS_BT_STATUS_SUCCESS) {
        return SOFTBUS_ERR;
    }
    g_isRegCb = true;
    return SOFTBUS_OK;
}

int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    if (listener == NULL) {
        return SOFTBUS_ERR;
    }
    if (RegisterListenerCallback() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    for (int index = 0; index < STATE_LISTENER_MAX_NUM; index++) {
        if (!g_stateListener[index].isUsed) {
            g_stateListener[index].isUsed = true;
            g_stateListener[index].listener = (SoftBusBtStateListener *)listener;
            return index;
        }
    }
    return SOFTBUS_ERR;
}

int SoftBusRemoveBtStateListener(int listenerId)
{
    if (listenerId < 0 || listenerId >= STATE_LISTENER_MAX_NUM) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_stateListener[listenerId].isUsed = false;
    g_stateListener[listenerId].listener = NULL;
    return SOFTBUS_OK;
}

int SoftBusEnableBt(void)
{
    if (EnableBle()) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int SoftBusDisableBt(void)
{
    if (DisableBle()) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_OK;
}

int SoftBusGetBtState(void)
{
    if (IsBleEnabled()) {
        return BLE_ENABLE;
    }
    return BLE_DISABLE;
}

int SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    if (!GetLocalAddr(mac->addr, BT_ADDR_LEN)) {
        return SOFTBUS_ERR;
    }
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
    if (SetLocalName((unsigned char *)name, strlen(name))) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}
