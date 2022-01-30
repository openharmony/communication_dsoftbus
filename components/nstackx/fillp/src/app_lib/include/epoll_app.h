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

#ifndef EPOLL_APP_H
#define EPOLL_APP_H
#include "epoll.h"

#ifdef __cplusplus
extern "C" {
#endif

FILLP_INT SpungeEpollCtl(FILLP_INT epFd, FILLP_INT op, FILLP_INT fd, FILLP_CONST struct SpungeEpollEvent *event);
FILLP_INT SpungeEpollFindRemove(FILLP_INT epFd, FILLP_INT fd);
FILLP_INT SpungeEpollWait(FILLP_INT epFd, struct SpungeEpollEvent *events, FILLP_INT maxEvents, FILLP_INT timeout);
FILLP_INT SpungeEpollCreate(void);

#ifdef __cplusplus
}
#endif

#endif
