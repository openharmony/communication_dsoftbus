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

#ifndef BUS_CENTER_MANAGER_STRUCT_H
#define BUS_CENTER_MANAGER_STRUCT_H
#include "disc_interface_struct.h"
#include "disc_manager_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LNN_MESSAGE_LANE = 1,
    LNN_BYTES_LANE,
    LNN_FILE_LANE,
    LNN_STREAM_LANE,
    LNN_LANE_PROPERTY_BUTT,
} LnnLaneProperty;

typedef union  {
    IServerDiscInnerCallback serverCb;
    DiscInnerCallback innerCb;
} InnerCallback;

#ifdef __cplusplus
}
#endif
#endif // BUS_CENTER_MANAGER_STRUCT_H