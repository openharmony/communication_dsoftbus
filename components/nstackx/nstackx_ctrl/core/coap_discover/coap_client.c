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
#define COAP_MULTICAST_ADDR "ff02::1"

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
        if (ainfo->ai_family != dst->sa_family) {
            continue;
        }
        len = ainfo->ai_addrlen;
        size_t dstLen = dst->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        if (memcpy_s(dst, dstLen, ainfo->ai_addr, len) != EOK) {
            DFINDER_LOGE(TAG, "ai_addr copy error");
            error = NSTACKX_EFAILED;
        }
        break;
    }
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

static int CoapBindToDevice(int sockfd, uint8_t af, const union InetAddr *addr)
{
    struct sockaddr_in sockIp;
    if (af == AF_INET) {
        (void)memset_s(&sockIp, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in));
        (void)memcpy_s(&sockIp.sin_addr, sizeof(struct in_addr), &(addr->in), sizeof(struct in_addr));
        return BindToDevice(sockfd, &sockIp);
    }
    return NSTACKX_EOK;
}

static int CoapAddIpv6Multicast(int sockfd)
{
    struct ipv6_mreq mreq;
    if (inet_pton(AF_INET6, COAP_MULTICAST_ADDR, &mreq.ipv6mr_multiaddr) <= 0) {
        DFINDER_LOGE(TAG, "inet_pton multicast addr fail");
        return NSTACKX_EFAILED;
    }
    mreq.ipv6mr_interface = 0; // use the default interface
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1) {
        DFINDER_LOGE(TAG, "setsockopt add multicast group fail");
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

coap_endpoint_t *CoapCreateEndpoint(coap_context_t *ctx, coap_address_t *addr,
    uint8_t af,  const union InetAddr *ip)
{
    DFINDER_LOGI(TAG, "Initializing CoapCreateEndpoint");
    coap_endpoint_t *ep = coap_new_endpoint(ctx, addr, COAP_PROTO_UDP);
    if (ep == NULL) {
        DFINDER_LOGE(TAG, "coap_new_endpoint get null");
        return NULL;
    }
    if (CoapBindToDevice(ep->sock.fd, af, ip) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "bind to device fail");
        coap_free_endpoint(ep);
        return NULL;
    }
    if (af == AF_INET6 && CoapAddIpv6Multicast(ep->sock.fd) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "add ipv6 multicast fail");
        coap_free_endpoint(ep);
        return NULL;
    }
    return ep;
}

static coap_context_t *CoapGetContextEx(const char *node, const char *port,
    uint8_t af, const union InetAddr *ip)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp = NULL;
    coap_endpoint_t *ep = NULL;
    coap_context_t *ctx = coap_new_context(NULL);
    if (ctx == NULL) {
        DFINDER_LOGE(TAG, "coap_new_context return null");
        return NULL;
    }
    InitAddrinfo(&hints);

    if (getaddrinfo(node, port, &hints, &result) != 0) {
        DFINDER_LOGE(TAG, "getaddrinfo fail, errno: %d, desc: %s", errno, strerror(errno));
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
        if (rp->ai_family != af || memcpy_s(&addr.addr, sizeof(addr.addr), rp->ai_addr, rp->ai_addrlen) != EOK) {
            continue;
        }
        ep = CoapCreateEndpoint(ctx, &addr, af, ip);
        if (ep == NULL) {
            DFINDER_LOGE(TAG, "coap_new_endpoint return null");
            coap_free_context(ctx);
            ctx = NULL;
        }
        break;
    }
    freeaddrinfo(result);
    return ctx;
}

coap_context_t *CoapGetContext(const char *node, const char *port,
    uint8_t af, const union InetAddr *ip)
{
    coap_context_t *context = CoapGetContextEx(node, port, af, ip);
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
        if (rp->ai_addrlen > (socklen_t)sizeof(bindAddr.addr) || rp->ai_addr == NULL ||
            dst->addr.sa.sa_family != rp->ai_addr->sa_family) {
            continue;
        }
        (void)memset_s(&bindAddr, sizeof(bindAddr), 0, sizeof(bindAddr));
        coap_address_init(&bindAddr);
        bindAddr.size = rp->ai_addrlen;
        if (memcpy_s(&bindAddr.addr, sizeof(bindAddr.addr), rp->ai_addr, rp->ai_addrlen) != EOK) {
            DFINDER_LOGE(TAG, "ai_addr copy error");
            continue;
        }
        char ip[NSTACKX_MAX_IP_STRING_LEN];
        if (bindAddr.addr.sa.sa_family == AF_INET) {
            (void)inet_ntop(AF_INET, &(bindAddr.addr.sin.sin_addr), ip, sizeof(ip));
        } else {
            (void)inet_ntop(AF_INET6, &(bindAddr.addr.sin6.sin6_addr), ip, sizeof(ip));
        }
        session = coap_new_client_session(ctx, &bindAddr, dst, proto);
        if (session != NULL) {
            break;
        } else {
            DFINDER_LOGE(TAG, "coap_new_client_session error");
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
            DFINDER_LOGE(TAG, "getaddrinfo failed, error: %d, desc: %s", errno, strerror(errno));
            return NULL;
        }
        session = CoapGetSessionInner(result, ctx, coapServerParameter);
        freeaddrinfo(result);
    } else {
        session = coap_new_client_session(ctx, NULL, dst, proto);
        if (session == NULL) {
            DFINDER_LOGE(TAG, "coap_new_client_session failed with null local addr");
        }
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
        DFINDER_LOGW(TAG, "coap context passed in is null");
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
