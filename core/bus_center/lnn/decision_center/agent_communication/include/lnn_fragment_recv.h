/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef LNN_FRAGMENT_RECV_H
#define LNN_FRAGMENT_RECV_H

#include <stdint.h>
#include <stdbool.h>

#include "softbus_error_code.h"
#include "lnn_device_cloud_convergence_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FRAGMENT_HEADER_SIZE  16
#define MODULE_TYPE_SIZE      4

// 初始化（模块初始化时调用）
void FragmentRecvInit(void);

// 销毁（模块退出时调用）
void FragmentRecvDeinit(void);

// 分片数据处理入口
int32_t FragmentRecvProcess(const char *udid, const uint8_t *data, uint32_t dataLen,
    ConversationChannelType channelType, FragmentRecvCallback callback);

// 清理指定msgId的缓存
void FragmentRecvClear(uint32_t msgId);

// 清理所有缓存（连接断开时）
void FragmentRecvClearAll(void);

#ifdef __cplusplus
}
#endif

#endif // LNN_FRAGMENT_RECV_H