/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * License under the Apache License, Version 2.0 (the "License");
 * you may not use this file expect in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permission and
 * limitations under the License.
 */

#include "lnn_meta_node_interface.h"

#include "softbus_common.h"
#include "softbus_errcode.h"

int32_t LnnLoadMetaNode(const int32_t tType)
{
    (void)tType;
    return SOFTBUS_OK;
}

int32_t LnnUnLoadMetaNode(const int32_t tType)
{
    (void)tType;
    return SOFTBUS_OK;
}

int32_t MetaNodeServerLeaveExt(const char *metaNodeId, MetaNodeType tType)
{
    (void)metaNodeId;
    (void)tType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t MetaNodeServerJoinExt(CustomData *customData)
{
    (void)customData;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnInitMetaNode(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitMetaNode(void)
{
    return;
}

MetaNodeType FindMetaNodeType(const char *metaNodeId)
{
    (void)metaNodeId;
    return CUSTOM_UNKNOWN;
}

int32_t LnnInitMetaNodeExtLedger(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitMetaNodeExtLedger(void)
{
    return;
}