/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef COAP_CLIENT_H
#define COAP_CLIENT_H

#include <coap3/coap.h>

#ifdef __cplusplus
extern "C" {
#endif

#define COAP_DEVICE_DISCOVER_URI "device_discover"
#define COAP_SERVICE_DISCOVER_URI "service_discover"
#define COAP_SERVICE_MSG_URI "service_msg"
#define COAP_SERVICE_NOTIFICATION_URI "short_notification_message"

typedef struct {
    coap_proto_t proto;
    const coap_address_t *dst;
} CoapServerParameter;

coap_context_t *CoapGetContext(const char *node, const char *port, uint8_t needBind, const struct in_addr *ip);
coap_session_t *CoapGetSession(coap_context_t *ctx, const char *localAddr, const char *localPort,
    const CoapServerParameter *coapServerParameter);

int32_t CoapResolveAddress(const coap_str_const_t *server, struct sockaddr *dst);
coap_response_t CoapMessageHandler(coap_session_t *session,
    const coap_pdu_t *sent, const coap_pdu_t *received, const coap_mid_t id);

uint8_t IsCoapCtxEndpointSocket(const coap_context_t *ctx, int fd);

#ifdef __cplusplus
}
#endif
#endif /* #ifndef COAP_CLIENT_H */
