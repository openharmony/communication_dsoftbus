/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef SYS_CONGESTION_H
#define SYS_CONGESTION_H

#include "nstackx_common_header.h"
#include "nstackx_congestion.h"

int32_t GetWifiInfo(const char *devName, WifiStationInfo *wifiStationInfo);
int32_t CheckDevNameValid(const char *devName);

#endif // SYS_CONGESTION_H