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

#ifndef LNN_DRIVER_REQUEST_H
#define LNN_DRIVER_REQUEST_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    LNN_DRIVER_MODULE_WLAN_PARAM = 0,
    LNN_DRIVER_MODULE_LWIP_MONITOR,
    LNN_DRIVER_MODULE_MAX_INDEX,
} LnnDriverModuleId;

int32_t LnnSendCmdToDriver(int32_t moduleId, const uint8_t *cmd, uint32_t cmdLen,
    uint8_t *reply, uint32_t replyLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* LNN_DRIVER_REQUEST_H */