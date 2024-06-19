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

#ifndef DATA_BUS_NATIVE_H
#define DATA_BUS_NATIVE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
int NotifyNearByUpdateMigrateOption(int channeId);

int NotifyNearByOnMigrateEvents(const char *peerDeviceId, int routeType, bool isUpgrade);

int NotifyNearByGetBrAgingTimeoutByBusName(const char *busName);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif // DATA_BUS_NATIVE_H
