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

#ifndef P2P_OPERATION_H
#define P2P_OPERATION_H

#include <future>
#include "p2p_operation_result.h"
#include "common_timer_errors.h"

namespace OHOS::SoftBus {
enum class P2pOperationType {
    CREATE_GROUP,
    CONNECT,
    DESTROY_GROUP,
};

struct P2pOperation {
    explicit P2pOperation(P2pOperationType type) : type_(type) {};
    virtual ~P2pOperation() = default;

    uint32_t timerId_ { Utils::TIMER_ERR_INVALID_VALUE };
    std::promise<P2pOperationResult> promise_;
    P2pOperationType type_;
};

template<typename Content>
struct P2pOperationWrapper : public P2pOperation {
    explicit P2pOperationWrapper(const Content &content, P2pOperationType type)
        : P2pOperation(type), content_(content) {};
    Content content_;
};
}
#endif