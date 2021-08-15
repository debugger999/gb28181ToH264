/**
 * @file sip_server.cpp
 * @brief
 * @author yanchaodong (yanchaodong@outlook.com)
 * @version 1.0
 * @date 2021-08-15
 *
 * @copyright Copyright (c) 2021 
 *
 * @par 修改日志:
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <eXosip2/eXosip.h>
#include <map>
#include <string>
#include "pstream.h"
#include "mediaServer.h"
#include "sip_server.h"


extern LocalPlatform g_LocalPlatform;
extern std::map<std::string, gb28181Params*> g_nvrid2nvrptr;
int init_udpsocket(int port, struct sockaddr_in* servaddr, char* mcast_addr)
{
    int err = -1;
    int socket_fd;

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        APP_ERR("socket failed, port:%d", port);
        return -1;
    }

    memset(servaddr, 0, sizeof(struct sockaddr_in));
    servaddr->sin_family = AF_INET;
    servaddr->sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr->sin_port = htons(port);

    err = bind(socket_fd, (struct sockaddr*)servaddr, sizeof(struct sockaddr_in));
    if (err < 0) {
        APP_ERR("bind failed, port:%d", port);
        return -2;
    }

    /*set enable MULTICAST LOOP */
    int loop = 1;
    err = setsockopt(socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
    if (err < 0) {
        APP_ERR("setsockopt IP_MULTICAST_LOOP failed, port:%d", port);
        return -3;
    }

    return socket_fd;
}

void release_udpsocket(int socket_fd, char* mcast_addr)
{
    close(socket_fd);
}


static void RegisterSuccess(struct eXosip_t* peCtx, eXosip_event_t* je)
{
    int iReturnCode = 0;
    osip_message_t* pSRegister = NULL;
    iReturnCode = eXosip_message_build_answer(peCtx, je->tid, 200, &pSRegister);
    if (iReturnCode == 0 && pSRegister != NULL)
    {
        eXosip_lock(peCtx);
        eXosip_message_send_answer(peCtx, je->tid, 200, pSRegister);
        eXosip_unlock(peCtx);
        //osip_message_free(pSRegister);
    }
}

void RegisterFailed(struct eXosip_t* peCtx, eXosip_event_t* je) {
    int iReturnCode = 0;
    osip_message_t* pSRegister = NULL;
    iReturnCode = eXosip_message_build_answer(peCtx, je->tid, 401, &pSRegister);
    if (iReturnCode == 0 && pSRegister != NULL)
    {
        eXosip_lock(peCtx);
        eXosip_message_send_answer(peCtx, je->tid, 401, pSRegister);
        eXosip_unlock(peCtx);
    }
}


static void* MainProcess(LocalPlatform* local_platform, void* pvSClientGB)
{
    char* p;
    int keepAliveFlag = 0;
    struct eXosip_t* peCtx = (struct eXosip_t*)pvSClientGB;

    while (g_LocalPlatform.running) {
        eXosip_event_t* je = NULL;

        je = eXosip_event_wait(peCtx, 0, 10);
        if (je == NULL) {
            osip_usleep(100000);
            continue;
        }

        switch (je->type) {
        case EXOSIP_MESSAGE_NEW:
        {
            //printf("new msg method:%s\n", je->request->sip_method);
            if (MSG_IS_REGISTER(je->request)) {
                APP_DEBUG("recv Register:%s", je->request->from);
                std::map<std::string, gb28181Params*>::iterator it;
                it = g_nvrid2nvrptr.find(je->request->from->url->username);
                if (it != g_nvrid2nvrptr.end()) {
                    it->second->registerOk = 1;
                }
            }
            else if (MSG_IS_MESSAGE(je->request)) {
                osip_body_t* body = NULL;
                osip_message_get_body(je->request, 0, &body);
                if (body != NULL) {
                    p = strstr(body->body, "Keepalive");
                    if (p != NULL) {
                        if (keepAliveFlag == 0) {
                            printf("msg body:%s\n", body->body);
                            keepAliveFlag = 1;
                            std::map<std::string, gb28181Params*>::iterator it;
                            it = g_nvrid2nvrptr.find(je->request->from->url->username);
                            if (it != g_nvrid2nvrptr.end()) {
                                it->second->registerOk = 1;
                            }
                        }
                    }
                    else {
                        printf("msg body:%s\n", body->body);
                    }
                }
                else {
                    APP_ERR("get body failed");
                }
            }
            else if (strncmp(je->request->sip_method, "BYE", 4) != 0) {
                APP_WARRING("unsupport new msg method : %s", je->request->sip_method);
            }
            RegisterSuccess(peCtx, je);
        }
        break;
        case EXOSIP_MESSAGE_ANSWERED:
        {
            printf("answered method:%s\n", je->request->sip_method);
            RegisterSuccess(peCtx, je);
        }
        break;
        case EXOSIP_CALL_ANSWERED:
        {
            osip_message_t* ack = NULL;
            // 判断是哪一台nvr
            std::map<std::string, gb28181Params*>::iterator it;
            it = g_nvrid2nvrptr.find(je->request->from->url->host);
            if (it != g_nvrid2nvrptr.end()) {
                it->second->call_id = je->cid;
                it->second->dialog_id = je->did;
                printf("call answered method:%s, call_id:%d, dialog_id:%d\n", je->request->sip_method,
                    it->second->call_id,
                    it->second->dialog_id);
            }
            eXosip_call_build_ack(peCtx, je->did, &ack);
            eXosip_lock(peCtx);
            eXosip_call_send_ack(peCtx, je->did, ack);
            eXosip_unlock(peCtx);
        }
        break;
        case EXOSIP_CALL_PROCEEDING:
        {
            printf("recv EXOSIP_CALL_PROCEEDING\n");
            RegisterSuccess(peCtx, je);
        }
        break;
        case EXOSIP_CALL_REQUESTFAILURE:
        {
            printf("recv EXOSIP_CALL_REQUESTFAILURE\n");
            RegisterSuccess(peCtx, je);
        }
        break;
        case EXOSIP_CALL_MESSAGE_ANSWERED:
        {
            printf("recv EXOSIP_CALL_MESSAGE_ANSWERED\n");
            RegisterSuccess(peCtx, je);
        }
        break;
        case EXOSIP_CALL_RELEASED:
        {
            printf("recv EXOSIP_CALL_RELEASED\n");
            RegisterSuccess(peCtx, je);
        }
        break;
        case EXOSIP_CALL_CLOSED:
        {
            printf("recv EXOSIP_CALL_CLOSED\n");
            RegisterSuccess(peCtx, je);
        }
        break;
        case EXOSIP_CALL_MESSAGE_NEW:
        {
            printf("recv EXOSIP_CALL_MESSAGE_NEW\n");
            RegisterSuccess(peCtx, je);
        }
        break;
        default:
        {
            printf("##test,%s:%d, unsupport type:%d\n", __FILE__, __LINE__, je->type);
            RegisterSuccess(peCtx, je);
        }
        break;
        }
        eXosip_event_free(je);
    }

    return NULL;
}


int sendInvitePlay(char* playSipId, int rtp_recv_port, gb28181Params* p28181Params)
{
    char dest_call[256], source_call[256], subject[128];
    osip_message_t* invite = NULL;
    int ret;
    struct eXosip_t* peCtx = g_LocalPlatform.eCtx;

    snprintf(dest_call, 256, "sip:%s@%s:%d", playSipId, p28181Params->platformIpAddr, p28181Params->platformSipPort);
    snprintf(source_call, 256, "sip:%s@%s", g_LocalPlatform.localSipId, g_LocalPlatform.localIpAddr);
    snprintf(subject, 128, "%s:0,%s:0", playSipId, g_LocalPlatform.localSipId);
    ret = eXosip_call_build_initial_invite(peCtx, &invite, dest_call, source_call, NULL, subject);
    if (ret != 0) {
        APP_ERR("eXosip_call_build_initial_invite failed, %s,%s,%s", dest_call, source_call, subject);
        return -1;
    }
    char body[2048];
    int bodyLen = snprintf(body, 2048,
        "v=0\r\n"
        "o=%s 0 0 IN IP4 %s\r\n"
        "s=Play\r\n"
        "c=IN IP4 %s\r\n"
        "t=0 0\r\n"
        "m=video %d RTP/AVP 96 97 98\r\n"
        "a=rtpmap:96 PS/90000\r\n"
        "a=rtpmap:97 MPEG4/90000\r\n"
        "a=rtpmap:98 H264/90000\r\n"
        "a=recvonly\r\n", playSipId, g_LocalPlatform.localIpAddr,
        g_LocalPlatform.localIpAddr, rtp_recv_port);
    osip_message_set_body(invite, body, bodyLen);
    osip_message_set_content_type(invite, "APPLICATION/SDP");
    eXosip_lock(peCtx);
    eXosip_call_send_initial_invite(peCtx, invite);
    eXosip_unlock(peCtx);

    return 0;
}

int sendPlayBye(gb28181Params* p28181Params)
{
    struct eXosip_t* peCtx = g_LocalPlatform.eCtx;

    eXosip_lock(peCtx);
    eXosip_call_terminate(peCtx, p28181Params->call_id, p28181Params->dialog_id);
    eXosip_unlock(peCtx);

    return 0;
}


int checkCameraStatus(liveVideoStreamParams* pliveVideoParams)
{
    int i;
    CameraParams* p;
    gb28181Params* p28181Params = &(pliveVideoParams->gb28181Param);

    for (i = 0; i < pliveVideoParams->cameraNum; i++) {
        p = pliveVideoParams->pCameraParams + i;
        if (p->status == 0) {
            p->statusErrCnt++;
            if (p->statusErrCnt % 10 == 0) {
                APP_WARRING("camera %s is exception, restart it", p->sipId);
                p28181Params->call_id = -1;
                sendInvitePlay(p->sipId, p->recvPort, p28181Params);
                p->statusErrCnt = 0;
            }
        }
        else {
            p->statusErrCnt = 0;
            p->status = 0;
        }
    }

    return 0;
}



void* gb28181ServerThread(void* arg)
{
    int iReturnCode = 0;
    struct eXosip_t* eCtx;
    LocalPlatform* local_platform = (LocalPlatform*)(arg);

    eCtx = eXosip_malloc();
    iReturnCode = eXosip_init(eCtx);
    if (iReturnCode != OSIP_SUCCESS) {
        APP_ERR("Can't initialize eXosip!");
        return NULL;
    }
    else {
        printf("eXosip_init successfully!\n");
    }

    iReturnCode = eXosip_listen_addr(eCtx, IPPROTO_UDP, NULL, local_platform->localSipPort, AF_INET, 0);
    if (iReturnCode != OSIP_SUCCESS) {
        APP_ERR("eXosip_listen_addr error!");
        return NULL;
    }

    local_platform->eCtx = eCtx;
    MainProcess(local_platform, eCtx);

    eXosip_quit(eCtx);
    osip_free(eCtx);
    eCtx = NULL;
    local_platform->eCtx = NULL;

    APP_DEBUG("%s run over", __func__);

    return 0;
}

