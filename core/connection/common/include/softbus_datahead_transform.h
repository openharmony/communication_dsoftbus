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

#ifndef SOFTBUS_DATAHEAD_TRANSFORM_H
#define SOFTBUS_DATAHEAD_TRANSFORM_H

#include <stdbool.h>
#include <stdint.h>
#include "softbus_conn_manager.h"
#include "softbus_proxychannel_message.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

void PackConnPktHead(ConnPktHead *data);
void UnpackConnPktHead(ConnPktHead *data);
void UnpackProxyMessageHead(ProxyMessageHead *msg);
void PackProxyMessageHead(ProxyMessageHead *msg);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_DATAHEAD_TRANSFORM_H */