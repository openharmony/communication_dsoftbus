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

#ifndef LNN_META_NODE_LEDGER_H
#define LNN_META_NODE_LEDGER_H

#include <stdint.h>

#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnInitMetaNodeLedger(void);
void LnnDeinitMetaNodeLedger(void);

int32_t LnnActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId);
int32_t LnnDeactiveMetaNode(const char *metaNodeId);
int32_t LnnGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum);
int32_t LnnGetMetaNodeInfoByNetworkId(const char *networkId, MetaNodeInfo *nodeInfo);
int32_t LnnGetMetaNodeUdidByNetworkId(const char *networkId, char *udid);

#ifdef __cplusplus
}
#endif

#endif // LNN_META_NODE_LEDGER_H