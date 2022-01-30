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

#ifndef SOCKET_OPT_H
#define SOCKET_OPT_H

#include "fillpinc.h"

#ifdef __cplusplus
extern "C" {
#endif

FILLP_INT SockGetSockOpt(FILLP_INT sockIndex, FILLP_INT level, FILLP_INT optName, void *optVal, FILLP_INT *optLen);

FILLP_INT SockSetSockOpt(FILLP_INT sockIndex, FILLP_INT level, FILLP_INT optName,
    FILLP_CONST void *optVal, socklen_t optLen);

#ifdef __cplusplus
}
#endif

#endif /* SOCKET_OPT_H */
