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
#include "softbus_error_code.h"

int32_t LnnInitMetaNode(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitMetaNode(void)
{
    return;
}

int32_t LnnInitMetaNodeExtLedger(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitMetaNodeExtLedger(void)
{
    return;
}

void ClearMetaNodeRequestByPid(const char *pkgName, int32_t pid)
{
    (void)pkgName;
    (void)pid;
}
