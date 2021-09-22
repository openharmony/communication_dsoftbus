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

int BleOhosStatusToSoftBus(BtStatus btStatus)
{
    int status;
    switch (btStatus) {
        case OHOS_BT_STATUS_SUCCESS:
            status = SOFTBUS_BT_STATUS_SUCCESS;
            break;
        case OHOS_BT_STATUS_FAIL:
            status = SOFTBUS_BT_STATUS_FAIL;
            break;
        case OHOS_BT_STATUS_NOT_READY:
            status = SOFTBUS_BT_STATUS_NOT_READY;
            break;
        case OHOS_BT_STATUS_NOMEM:
            status = SOFTBUS_BT_STATUS_NOMEM;
            break;
        case OHOS_BT_STATUS_BUSY:
            status = SOFTBUS_BT_STATUS_BUSY;
            break;
        case OHOS_BT_STATUS_DONE:
            status = SOFTBUS_BT_STATUS_DONE;
            break;
        case OHOS_BT_STATUS_UNSUPPORTED:
            status = SOFTBUS_BT_STATUS_UNSUPPORTED;
            break;
        case OHOS_BT_STATUS_PARM_INVALID:
            status = SOFTBUS_BT_STATUS_PARM_INVALID;
            break;
        case OHOS_BT_STATUS_UNHANDLED:
            status = SOFTBUS_BT_STATUS_UNHANDLED;
            break;
        case OHOS_BT_STATUS_AUTH_FAILURE:
            status = SOFTBUS_BT_STATUS_AUTH_FAILURE;
            break;
        case OHOS_BT_STATUS_RMT_DEV_DOWN:
            status = SOFTBUS_BT_STATUS_RMT_DEV_DOWN;
            break;
        case OHOS_BT_STATUS_AUTH_REJECTED:
            status = SOFTBUS_BT_STATUS_AUTH_REJECTED;
            break;
        default:
            status = SOFTBUS_BT_STATUS_FAIL;
            break;
    }
    return status;
}