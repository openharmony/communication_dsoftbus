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

#include "coap_client.h"
#include <stdlib.h>
#include <string.h>
#include <securec.h>
#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <coap3/coap_session_internal.h>
#include "nstackx_device.h"
#include "nstackx_error.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_util.h"
#include "nstackx_statistics.h"

#define TAG "nStackXCoAP"

#define FLAGS_BLOCK 0x01
#define DEFAULT_COAP_BUFFER_LENGTH 256
#define COAP_CERT_CHAIN_DEPTH 2

/*
 * the initial timeout will be set to a random duration between COAP_ACK_TIMEOUT and
 * (COAP_ACK_TIMEOUT * COAP_ACK_RANDOM_FACTOR).
 */
#define DFINDER_COAP_ACK_TIMEOUT ((coap_fixed_point_t){1, 0}) // 1 seconds
#define DFINDER_COAP_ACK_RANDOM_FACTOR ((coap_fixed_point_t){1, 200}) // 1.2
#define DFINDER_COAP_MAX_RETRANSMIT_TIMES 2 // retransmit 2 times for CON packets

int32_t CoapResolveAddress(const coap_str_const_t *server, struct sockaddr *dst)
{
    struct addrinfo *res = NULL;
    struct addrinfo *ainfo = NULL;
    struct addrinfo hints;
    char addrstr[DEFAULT_COAP_BUFFER_LENGTH]; /* Get a char array with length 256 to save host name. */

    if (server == NULL || server->s == NULL || dst == NULL) {
        return NSTACKX_EINVAL;
    }
    (void)memset_s(addrstr, sizeof(addrstr), 0, sizeof(addrstr));
    if (server->length) {
        if (memcpy_s(addrstr, sizeof(addrstr), server->s, server->length) != EOK) {
            DFINDER_LOGD(TAG, "addrstr copy error");
            return NSTACKX_EFAILED;
        }
    } else {
        if (memcpy_s(addrstr, sizeof(addrstr), "localhost", strlen("localhost")) != EOK) {
            DFINDER_LOGD(TAG, "addrstr copy error");
            return NSTACKX_EFAILED;
        }
    }

    (void)memset_s((char *)&hints, sizeof(hints), 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    int32_t error = getaddrinfo(addrstr, NULL, &hints, &res);
    if (error != 0) {
        DFINDER_LOGE(TAG, "getaddrinfo error");
        return error;
    }

    socklen_t len = 0;
    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        switch (ainfo->ai_family) {
            case AF_INET6:
                /* fall-through */
            case AF_INET:
                len = ainfo->ai_addrlen;
                if (memcpy_s(dst, sizeof(struct sockaddr), ainfo->ai_addr, (size_t)len) != EOK) {
                    DFINDER_LOGE(TAG, "ai_addr copy error");
                    error = NSTACKX_EFAILED;
                    goto finish;
                }
                break;
            default:
                break;
        }
    }

finish:
    freeaddrinfo(res);
    return (error == NSTACKX_EFAILED) ? error : (int32_t)len;
}

coap_response_t CoapMessageHandler(coap_session_t *session,
    const coap_pdu_t *sent, const coap_pdu_t *received, const coap_mid_t id)
{
    if (received == NULL) {
        DFINDER_LOGE(TAG, "received error");
        goto FAIL;
    }
    (void)session;
    (void)sent;
    (void)id;
    coap_opt_t *blockOpt1 = NULL;
    coap_opt_t *blockOpt2 = NULL;
    coap_opt_iterator_t optIter;

    (void)memset_s(&optIter, sizeof(optIter), 0, sizeof(optIter));
    if (coap_pdu_get_type(received) == COAP_MESSAGE_RST) {
        DFINDER_LOGD(TAG, "got RST");
        goto FAIL;
    }

    if (coap_check_option(received, COAP_OPTION_OBSERVE, &optIter)) {
        DFINDER_LOGE(TAG, "observe not support.");
        goto FAIL;
    }
    blockOpt2 = coap_check_option(received, COAP_OPTION_BLOCK2, &optIter);
    blockOpt1 = coap_check_option(received, COAP_OPTION_BLOCK1, &optIter);
    if ((blockOpt1 != NULL) || (blockOpt2 != NULL)) {
        DFINDER_LOGE(TAG, "block not support.");
        goto FAIL;
    }

    coap_pdu_code_t rcv_code = coap_pdu_get_code(received);
    DFINDER_LOGD(TAG, "%d.%02d", COAP_RESPONSE_CLASS(rcv_code), rcv_code & 0x1F);
    return COAP_RESPONSE_OK;

FAIL:
    IncStatistics(STATS_INVALID_RESPONSE_MSG);
    return COAP_RESPONSE_FAIL;
}

static void InitAddrinfo(struct addrinfo *hints)
{
    if (hints == NULL) {
        return;
    }
    (void)memset_s(hints, sizeof(struct addrinfo), 0, sizeof(struct addrinfo));
    hints->ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints->ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints->ai_flags = AI_PASSIVE | AI_NUMERICHOST;
}

static coap_context_t *CoapGetContextEx(const char *node, const char *port,
    uint8_t needBind, const struct in_addr *ip)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp = NULL;
    coap_endpoint_t *ep = NULL;
    coap_context_t *ctx = coap_new_context(NULL);
    if (ctx == NULL) {
        return NULL;
    }
    InitAddrinfo(&hints);

    if (getaddrinfo(node, port, &hints, &result) != 0) {
        coap_free_context(ctx);
        return NULL;
    }
    coap_address_t addr;
    /* iterate through results until success */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_addrlen > (socklen_t)sizeof(addr.addr)) {
            continue;
        }

        coap_address_init(&addr);
        addr.size = rp->ai_addrlen;
        if (memcpy_s(&addr.addr, sizeof(addr.addr), rp->ai_addr, rp->ai_addrlen) != EOK ||
            (addr.addr.sa.sa_family != AF_INET && addr.addr.sa.sa_family != AF_INET6)) {
            continue;
        }

        ep = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
        if (ep != NULL) {
            struct sockaddr_in sockIp;
            struct sockaddr_in *sockIpPtr = NULL;
            (void)memset_s(&sockIp, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in));
            if (ip != NULL && needBind) {
                (void)memcpy_s(&sockIp.sin_addr, sizeof(struct in_addr), ip, sizeof(struct in_addr));
                sockIpPtr = &sockIp;
            }
            if (needBind && BindToDevice(ep->sock.fd, sockIpPtr) != NSTACKX_EOK) {
                DFINDER_LOGE(TAG, "bind to device fail");
                coap_free_context(ctx);
                ctx = NULL;
            }
        } else {
            DFINDER_LOGE(TAG, "coap_new_endpoint get null");
            coap_free_context(ctx);
            ctx = NULL;
        }
        break;
    }
    freeaddrinfo(result);
    return ctx;
}

coap_context_t *CoapGetContext(const char *node, const char *port, uint8_t needBind, const struct in_addr *ip)
{
    coap_context_t *context = CoapGetContextEx(node, port, needBind, ip);
    if (context == NULL) {
        IncStatistics(STATS_CREATE_CONTEX_FAILED);
    }
    return context;
}

static coap_session_t *CoapGetSessionInner(struct addrinfo *result, coap_context_t *ctx,
    const CoapServerParameter *coapServerParameter)
{
    coap_session_t *session = NULL;
    struct addrinfo *rp = NULL;
    coap_proto_t proto = coapServerParameter->proto;
    const coap_address_t *dst = coapServerParameter->dst;

    if (proto != COAP_PROTO_UDP) {
        DFINDER_LOGE(TAG, "unsupported proto");
        return NULL;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        coap_address_t bindAddr;
        if (rp->ai_addrlen > (socklen_t)sizeof(bindAddr.addr) || rp->ai_addr == NULL) {
            continue;
        }
        coap_address_init(&bindAddr);
        bindAddr.size = rp->ai_addrlen;
        if (memcpy_s(&bindAddr.addr, sizeof(bindAddr.addr), rp->ai_addr, rp->ai_addrlen) != EOK) {
            DFINDER_LOGE(TAG, "ai_addr copy error");
            continue;
        }
        session = coap_new_client_session(ctx, &bindAddr, dst, proto);
        if (session != NULL) {
            break;
        }
    }
    return session;
}

static void CoapSetAckTimeOut(coap_session_t *session)
{
    if (session == NULL) {
        return;
    }
    coap_session_set_ack_timeout(session, DFINDER_COAP_ACK_TIMEOUT);
    coap_session_set_ack_random_factor(session, DFINDER_COAP_ACK_RANDOM_FACTOR);
    coap_session_set_max_retransmit(session, DFINDER_COAP_MAX_RETRANSMIT_TIMES);
}

static coap_session_t *CoapGetSessionEx(coap_context_t *ctx, const char *localAddr, const char *localPort,
    const CoapServerParameter *coapServerParameter)
{
    coap_session_t *session = NULL;
    coap_proto_t proto;
    const coap_address_t *dst = NULL;

    if (coapServerParameter == NULL) {
        return NULL;
    }

    proto = coapServerParameter->proto;
    dst = coapServerParameter->dst;
    if (proto != COAP_PROTO_UDP) {
        DFINDER_LOGE(TAG, "unsupported proto");
        return NULL;
    }

    if (dst == NULL) {
        return session;
    }

    /* reuse the existed session */
    session = coap_session_get_by_peer(ctx, dst, 0);
    if (session != NULL) {
        CoapSetAckTimeOut(session);
        (void)coap_session_reference(session);
        return session;
    }

    if (localAddr != NULL) {
        struct addrinfo hints;
        struct addrinfo *result = NULL;

        (void)memset_s(&hints, sizeof(struct addrinfo), 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
        hints.ai_socktype = COAP_PROTO_RELIABLE(proto) ? SOCK_STREAM : SOCK_DGRAM; /* Coap uses UDP */
        hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
        int s = getaddrinfo(localAddr, localPort, &hints, &result);
        if (s != 0) {
            DFINDER_LOGE(TAG, "getaddrinfo error");
            return NULL;
        }
        session = CoapGetSessionInner(result, ctx, coapServerParameter);
        freeaddrinfo(result);
    } else {
        session = coap_new_client_session(ctx, NULL, dst, proto);
    }
    CoapSetAckTimeOut(session);
    return session;
}

coap_session_t *CoapGetSession(coap_context_t *ctx, const char *localAddr, const char *localPort,
    const CoapServerParameter *coapServerParameter)
{
    coap_session_t *session = CoapGetSessionEx(ctx, localAddr, localPort, coapServerParameter);
    if (session == NULL) {
        IncStatistics(STATS_CREATE_SESSION_FAILED);
    }
    return session;
}

uint8_t IsCoapCtxEndpointSocket(const coap_context_t *ctx, int fd)
{
    coap_endpoint_t *iterator = NULL;
    coap_endpoint_t *listeningEndpoints = NULL;
    coap_endpoint_t *tmp = NULL;
    if (ctx == NULL) {
        return NSTACKX_FALSE;
    }
    listeningEndpoints = coap_context_get_endpoint(ctx);
    LL_FOREACH_SAFE(listeningEndpoints, iterator, tmp) {
        if (iterator->sock.fd == fd) {
            return NSTACKX_TRUE;
        }
    }
    return NSTACKX_FALSE;
}
