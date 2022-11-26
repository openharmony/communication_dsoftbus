/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef SESSION_CALLBACK_MOCK_H
#define SESSION_CALLBACK_MOCK_H

#ifdef __cplusplus
extern "C" {
#endif

int InnerOnSessionOpened(int sessionId, int result);

void InnerOnSessionClosed(int sessionId);

void InnerOnBytesReceived(int sessionId, const void *data, unsigned int dataLen);

void InnerOnMessageReceived(int sessionId, const void *data, unsigned int dataLen);

#ifdef __cplusplus
}
#endif
#endif // SESSION_CALLBACK_MOCK_H