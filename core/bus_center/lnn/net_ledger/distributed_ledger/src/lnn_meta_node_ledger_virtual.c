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

#include "lnn_meta_node_ledger.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnInitMetaNodeLedger(void)
{
    LNN_LOGI(LNN_INIT, "meta node virtual init success");
    return SOFTBUS_OK;
}

void LnnDeinitMetaNodeLedger(void)
{
}

int32_t LnnActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    (void)info;
    (void)metaNodeId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeactiveMetaNode(const char *metaNodeId)
{
    (void)metaNodeId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    (void)infos;
    (void)infoNum;
    return SOFTBUS_NOT_IMPLEMENT;
}