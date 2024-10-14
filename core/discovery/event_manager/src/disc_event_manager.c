/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "disc_approach_ble.h"
#include "disc_event_manager.h"
#include "disc_log.h"
#include "disc_touch_ble.h"
#include "disc_virtual_link_ble.h"
#include "softbus_error_code.h"

int32_t DiscEventManagerInit(void)
{
    int32_t ret = DiscApproachBleEventInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_INIT, "init approach ble event failed");

    ret = DiscVLinkBleEventInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_INIT, "init vlink ble event failed");

    ret = DiscTouchBleEventInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_INIT, "init touch ble event failed");

    DISC_LOGI(DISC_INIT, "disc event manager init succ");
    return SOFTBUS_OK;
}

void DiscEventManagerDeinit(void)
{
    DiscApproachBleEventDeinit();
    DiscVLinkBleEventDeinit();
    DiscTouchBleEventDeinit();
}

