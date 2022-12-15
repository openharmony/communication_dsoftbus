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

#ifndef LNN_SYNC_LEDGER_ITEM_INFO_H
#define LNN_SYNC_LEDGER_ITEM_INFO_H

#include <stdint.h>

#include "lnn_node_info.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnSendTransReq(const char *peerNetWorkId, const BssTransInfo *transInfo);
int32_t LnnInitOffline(void);
void LnnDeinitOffline(void);

#ifdef __cplusplus
}
#endif
#endif // LNN_SYNC_LEDGER_ITEM_INFO_H
