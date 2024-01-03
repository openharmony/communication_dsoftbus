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

#include "adapter_bt_utils.h"

OhosStatusToSoftBus BleStatus[] = {
    {OHOS_BT_STATUS_SUCCESS,            SOFTBUS_BT_STATUS_SUCCESS},
    {OHOS_BT_STATUS_FAIL,               SOFTBUS_BT_STATUS_FAIL},
    {OHOS_BT_STATUS_NOT_READY,          SOFTBUS_BT_STATUS_NOT_READY},
    {OHOS_BT_STATUS_NOMEM,              SOFTBUS_BT_STATUS_NOMEM},
    {OHOS_BT_STATUS_BUSY,               SOFTBUS_BT_STATUS_BUSY},
    {OHOS_BT_STATUS_DONE,               SOFTBUS_BT_STATUS_DONE},
    {OHOS_BT_STATUS_UNSUPPORTED,        SOFTBUS_BT_STATUS_UNSUPPORTED},
    {OHOS_BT_STATUS_PARM_INVALID,       SOFTBUS_BT_STATUS_PARM_INVALID},
    {OHOS_BT_STATUS_UNHANDLED,          SOFTBUS_BT_STATUS_UNHANDLED},
    {OHOS_BT_STATUS_AUTH_FAILURE,       SOFTBUS_BT_STATUS_AUTH_FAILURE},
    {OHOS_BT_STATUS_RMT_DEV_DOWN,       SOFTBUS_BT_STATUS_RMT_DEV_DOWN},
    {OHOS_BT_STATUS_AUTH_REJECTED,      SOFTBUS_BT_STATUS_AUTH_REJECTED},
};

int32_t BleOhosStatusToSoftBus(BtStatus btStatus)
{
    int32_t status = OHOS_BT_STATUS_FAIL;
    const int len = sizeof(BleStatus) / sizeof(BleStatus[0]);
    OhosStatusToSoftBus *ptr = BleStatus;

    if (btStatus >= len) {
        return status;
    }

    return (ptr + btStatus)->softBusBtStatus;
}