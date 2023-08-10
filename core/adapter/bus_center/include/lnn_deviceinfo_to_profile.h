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

#ifndef DEVICEINFO_TO_PROFILE_H
#define DEVICEINFO_TO_PROFILE_H

#include <stdint.h>
#include "lnn_node_info.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

void InsertToProfile(NodeInfo *info);
void InsertMetaNodeInfoToProfile(MetaNodeInfo *info);
void UpdateProfile(const NodeInfo *info);
void UpdateMetaNodeProfile(MetaNodeInfo *info);
void DeleteFromProfile(const char *udid);
void ClearProfile();

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* DEVICEINFO_TO_PROFILE_H */