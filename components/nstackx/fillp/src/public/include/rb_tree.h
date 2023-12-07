/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FILLP_RB_TREE_H
#define FILLP_RB_TREE_H
#include "fillp_os.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RB_RED 0
#define RB_BLACK 1

struct RbNode {
    struct RbNode *rbParent;
    struct RbNode *rbRight;
    struct RbNode *rbLeft;
    FILLP_UINT color;

#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd[4];
#endif
};

struct RbRoot {
    struct RbNode *rbNode;
};

void FillpRbInsertColor(struct RbNode *x, struct RbRoot *root);
void FillpRbErase(struct RbNode *xNode, struct RbRoot *root);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_RB_TREE_H */