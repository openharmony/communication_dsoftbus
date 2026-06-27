/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
 
#ifndef NAPI_AGENT_COMMUNICATION_ERROR_CODE_
#define NAPI_AGENT_COMMUNICATION_ERROR_CODE_
 
#define CONVERSATION_OK                             0
 
#define CONVERSATION_PERMISSION_ERR                 201
#define CONVERSATION_PERMISSION_SYSTEMAPI_ERR       202
#define CONVERSATION_INVALID_PARAM                  401
 
#define CONVERSATION_INTERNAL_ERR                   2000001
#define CONVERSATION_INTERNAL_REMOTE_NOT_SUPPORT    2004001
#define CONVERSATION_DUPLICATE_CALLS                2004002
#define CONVERSATION_SEND_DATA_FAILED               2004003
#define CONVERSATION_WAIT_ACK_TIMEOUT               2004004
 
#endif /* NAPI_AGENT_COMMUNICATION_ERROR_CODE_ */