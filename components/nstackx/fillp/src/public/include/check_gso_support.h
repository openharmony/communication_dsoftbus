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

#ifndef CHECK_GSO_SUPPORT_H
#define CHECK_GSO_SUPPORT_H
#ifdef FILLP_SUPPORT_GSO
#include "utils.h"

extern FILLP_INT g_gsoSupport;

#ifndef CFG_MSS
#define CFG_MSS 1472
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

void CheckGSOSupport(void);
#endif
#endif /* CHECK_GSO_SUPPORT_H */
