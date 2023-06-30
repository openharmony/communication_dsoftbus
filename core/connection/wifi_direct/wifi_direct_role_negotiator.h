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
#ifndef WIFI_DIRECT_ROLE_NEGOTIATOR_H
#define WIFI_DIRECT_ROLE_NEGOTIATOR_H

#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectRoleNegotiator {
    enum WifiDirectRole (*getFinalRoleWithPeerExpectedRole)(enum WifiDirectRole myRole, enum WifiDirectRole peerRole,
                                                            enum WifiDirectRole expectedRole, const char *myGoMac,
                                                            const char *remoteGoMac);
};

struct WifiDirectRoleNegotiator *GetRoleNegotiator(void);

#ifdef __cplusplus
}
#endif
#endif