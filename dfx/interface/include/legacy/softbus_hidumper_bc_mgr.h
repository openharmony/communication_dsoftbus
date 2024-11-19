/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_HIDUMPER_BC_MGR_H
#define SOFTBUS_HIDUMPER_BC_MGR_H

#include "legacy/softbus_hidumper.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t SoftBusBcMgrHiDumperInit(void);
int32_t SoftBusRegBcMgrVarDump(const char *dumpVar, SoftBusVarDumpCb cb);
void SoftBusHiDumperBcMgrDeInit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_HIDUMPER_BC_MGR_H */