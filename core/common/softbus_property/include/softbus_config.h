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

#ifndef SOFTBUS_CONFIG_H
#define SOFTBUS_CONFIG_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

static const char* SOFTBUS_CONFIG =
"{\
\"MAX_BYTES_LENGTH\" : 4194304,\
\"MAX_MESSAGE_LENGTH\" : 4096,\
\"CONN_BR_MAX_DATA_LENGTH\" : 4096,\
\"CONN_RFCOM_SEND_MAX_LEN\" : 990,\
\"CONN_BR_RECEIVE_MAX_LEN\" : 10,\
\"CONN_TCP_MAX_LENGTH\" : 3072,\
\"CONN_TCP_MAX_CONN_NUM\" : 30,\
\"CONN_TCP_TIME_OUT\" : 100,\
\"MAX_NODE_STATE_CB_CNT\" : 10\
}";

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif // SOFTBUS_CONFIG_H