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

#ifndef LNN_TOPO_MANAGER_H
#define LNN_TOPO_MANAGER_H

#include <stdint.h>

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char udid[UDID_BUF_LEN];
    char peerUdid[UDID_BUF_LEN];
    uint8_t relation[CONNECTION_ADDR_MAX];
} LnnRelation;

typedef struct {
    ConnectionAddrType type;
    uint8_t relation;
    bool isJoin;
    char udid[UDID_BUF_LEN];
} LnnRelationChangedMsg;

int32_t LnnInitTopoManager(void);
void LnnDeinitTopoManager(void);

int32_t LnnGetAllRelation(LnnRelation **relation, uint32_t *relationNum);
int32_t LnnGetRelation(const char *udid, const char *peerUdid, uint8_t *relation, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif // LNN_TOPO_MANAGER_H
