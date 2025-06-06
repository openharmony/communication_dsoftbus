/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_P2P_INFO_H
#define LNN_P2P_INFO_H

#include "lnn_node_info.h"
#include "softbus_json_utils.h"
#include "lnn_p2p_info_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnInitP2p(void);
void LnnDeinitP2p(void);
int32_t LnnInitLocalP2pInfo(NodeInfo *info);
int32_t LnnSyncP2pInfo(void);
int32_t LnnSyncWifiDirectAddr(void);
int32_t LnnInitWifiDirect(void);
void LnnDeinitWifiDirect(void);

#ifdef __cplusplus
}
#endif

#endif // LNN_P2P_INFO_H