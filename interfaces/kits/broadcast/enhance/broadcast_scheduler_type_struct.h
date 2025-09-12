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

#ifndef BROADCAST_SCHEDULER_TYPE_STRUCT_H
#define BROADCAST_SCHEDULER_TYPE_STRUCT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BC_TYPE_DISTRIB_CON,
    BC_TYPE_DISTRIB_NON,
    BC_TYPE_SHARE_CON,
    BC_TYPE_SHARE_NON,
    BC_TYPE_APPROACH,
    BC_TYPE_LINK_HML,
    BC_TYPE_LINK_BLE_DIRECT,
    BC_TYPE_LINK_HML_RSP,
    BC_TYPE_NOTIFY_FOREGROUND,
    BC_TYPE_NOTIFY_CLIP_BROAD,
    BC_TYPE_HB_CON_FAST,
    BC_TYPE_HB_CON,
    BC_TYPE_HB_NON,
    BC_TYPE_HB_LOW,
    BC_TYPE_HB_EXTREMELY_LOW,
    BC_TYPE_SH_HB,
    BC_TYPE_SH_BURST,
    BC_TYPE_FAST_OFFLINE,
    BC_TYPE_NOTIFY_ORIENTATION_RANGE,
    BC_TYPE_TOUCH,
    BC_TYPE_OOP,
    BC_TYPE_AUTH_LINK,
    BC_TYPE_D2D_PAGING_CON,
    BC_TYPE_D2D_PAGING_NON,
    BC_TYPE_D2D_GROUP_TALKIE_CTRL,
    BC_TYPE_D2D_GROUP_TALKIE_DATA,
    BC_TYPE_SD,
    BC_TYPE_SCHEDULER_BUTT,
} BroadcastContentType;

#ifdef __cplusplus
}
#endif

#endif // BROADCAST_SCHEDULER_TYPE_STRUCT_H