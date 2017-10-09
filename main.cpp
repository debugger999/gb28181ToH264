#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <eXosip2/eXosip.h>
#include "cJSON.h"
#include "mxml.h"
#include "HTTPDigest.h"
#include "mediaServer.h"
#include "pstream.h"

liveVideoStreamParams g_liveVideoParams;

static void RegisterSuccess(struct eXosip_t * peCtx,eXosip_event_t *je)
{
    int iReturnCode = 0 ;
    osip_message_t * pSRegister = NULL;
    iReturnCode = eXosip_message_build_answer (peCtx,je->tid,200,&pSRegister);
    if ( iReturnCode == 0 && pSRegister != NULL )
    {
        eXosip_lock(peCtx);
        eXosip_message_send_answer (peCtx,je->tid,200,pSRegister);
        eXosip_unlock(peCtx);
        //osip_message_free(pSRegister);
    }
}

void RegisterFailed(struct eXosip_t * peCtx,eXosip_event_t *je) {
    int iReturnCode = 0 ;
    osip_message_t * pSRegister = NULL;
    iReturnCode = eXosip_message_build_answer (peCtx,je->tid,401,&pSRegister);
    if ( iReturnCode == 0 && pSRegister != NULL )
    {
        eXosip_lock(peCtx);
        eXosip_message_send_answer (peCtx,je->tid,401,pSRegister);
        eXosip_unlock(peCtx);
    }
}
static int doParaseJson(char *buf) {
    int i;

    cJSON * root = cJSON_Parse(buf);
    if(root != NULL) {
        cJSON * pSubRoot = cJSON_GetObjectItem(root, "gb28181");
        if(pSubRoot != NULL) {
            cJSON * pSub = cJSON_GetObjectItem(pSubRoot, "platform_id");
            if(pSub != NULL) {
                APP_DEBUG("platform_id:%s", pSub->valuestring);
                strncpy(g_liveVideoParams.gb28181Param.platformSipId, pSub->valuestring, 256);
            }
            pSub = cJSON_GetObjectItem(pSubRoot, "platform_port");
            if(pSub != NULL) {
                APP_DEBUG("platform_port:%d", pSub->valueint);
                g_liveVideoParams.gb28181Param.platformSipPort = pSub->valueint;
            }
            pSub = cJSON_GetObjectItem(pSubRoot, "platform_ip");
            if(pSub != NULL) {
                APP_DEBUG("platform_ip:%s", pSub->valuestring);
                strncpy(g_liveVideoParams.gb28181Param.platformIpAddr, pSub->valuestring, 128);
            }
            pSub = cJSON_GetObjectItem(pSubRoot, "local_id");
            if(pSub != NULL) {
                APP_DEBUG("local_id:%s", pSub->valuestring);
                strncpy(g_liveVideoParams.gb28181Param.localSipId, pSub->valuestring, 256);
            }
            pSub = cJSON_GetObjectItem(pSubRoot, "local_port");
            if(pSub != NULL) {
                APP_DEBUG("local_port:%d", pSub->valueint);
                g_liveVideoParams.gb28181Param.localSipPort = pSub->valueint;
            }
            pSub = cJSON_GetObjectItem(pSubRoot, "local_ip");
            if(pSub != NULL) {
                APP_DEBUG("local_ip:%s", pSub->valuestring);
                strncpy(g_liveVideoParams.gb28181Param.localIpAddr, pSub->valuestring, 128);
            }
        }
        else {
            APP_ERR("err");
        }
        cJSON *pSub = cJSON_GetObjectItem(root, "camera_num");
        if(pSub != NULL) {
            APP_DEBUG("camera_num:%d", pSub->valueint);
            g_liveVideoParams.cameraNum = pSub->valueint;
            if(g_liveVideoParams.cameraNum > 0 && g_liveVideoParams.cameraNum < CAMERA_SUPPORT_MAX) {
                g_liveVideoParams.pCameraParams = (CameraParams *)malloc(sizeof(CameraParams)*g_liveVideoParams.cameraNum);
                if(g_liveVideoParams.pCameraParams == NULL) {
                    APP_ERR("malloc failed");
                    return -1;
                }
                memset(g_liveVideoParams.pCameraParams, 0, sizeof(CameraParams)*g_liveVideoParams.cameraNum);
                CameraParams *p;
                char cameraName[32];
                for(i = 0; i < g_liveVideoParams.cameraNum; i ++) {
                    p = g_liveVideoParams.pCameraParams + i;
                    snprintf(cameraName, 32, "camera%d_sip_id", i + 1);
                    pSub = cJSON_GetObjectItem(root, cameraName);
                    if(pSub != NULL) {
                        APP_DEBUG("%s:%s", cameraName, pSub->valuestring);
                        strncpy(p->sipId, pSub->valuestring, 256);
                    }
                    else {
                        APP_WARRING("get json failed, %s", cameraName);
                    }
                    snprintf(cameraName, 32, "camera%d_recv_port", i + 1);
                    pSub = cJSON_GetObjectItem(root, cameraName);
                    if(pSub != NULL) {
                        APP_DEBUG("%s:%d", cameraName, pSub->valueint);
                        p->recvPort = pSub->valueint;
                    }
                    else {
                        APP_WARRING("get json failed, %s", cameraName);
                    }
                }
            }
            else {
                APP_WARRING("err cameraNum : %d", g_liveVideoParams.cameraNum);
            }
        }
        cJSON_Delete(root);
    }
    else {
        APP_ERR("err, buf:%s", buf);
    }
    
    return 0;
}

static int initParams(char *jsonCfgFile) {
    char *buf = NULL;

    memset(&g_liveVideoParams, 0, sizeof(g_liveVideoParams));
    FILE *fp = fopen(jsonCfgFile, "rb");
    if(fp != NULL) {
        fseek(fp, 0L, SEEK_END);
        int cfgSie = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        buf = (char *)malloc(cfgSie/1024*1024 + 1024);
        if(buf == NULL) {
            APP_ERR("malloc failed");
            goto err;
        }
        if(fread(buf, 1, cfgSie, fp)) {
        }
        doParaseJson(buf);
    }
    else {
        APP_ERR("fopen %s failed", jsonCfgFile);
    }
    g_liveVideoParams.gb28181Param.SN = 1;
    g_liveVideoParams.gb28181Param.call_id = -1;
    g_liveVideoParams.gb28181Param.dialog_id = -1;
    g_liveVideoParams.gb28181Param.registerOk = 0;

err:
    if(buf != NULL) {
        free(buf);
    }
    if(fp != NULL) {
        fclose(fp);
    }

    return 0;
}

static void *MainProcess(gb28181Params *p28181Params, void * pvSClientGB) {
    char *p;
    int keepAliveFlag = 0;
    struct eXosip_t * peCtx = (struct eXosip_t *)pvSClientGB;

    while(p28181Params->running) {
        eXosip_event_t *je = NULL;

        je = eXosip_event_wait (peCtx, 0, 4);
        if (je == NULL) {
            osip_usleep(100000);
            continue;
        }

        switch (je->type) {
            case EXOSIP_MESSAGE_NEW:
                {
                    //printf("new msg method:%s\n", je->request->sip_method);
                    if(MSG_IS_REGISTER(je->request)) {
                        APP_DEBUG("recv Register");
                        g_liveVideoParams.gb28181Param.registerOk = 1;
                    }
                    else if(MSG_IS_MESSAGE(je->request)){
                        osip_body_t *body = NULL;
                        osip_message_get_body(je->request, 0, &body);
                        if(body != NULL) {
                            p = strstr(body->body, "Keepalive");
                            if(p != NULL) {
                                if(keepAliveFlag == 0) {
                                    printf("msg body:%s\n", body->body);
                                    keepAliveFlag = 1;
                                    g_liveVideoParams.gb28181Param.registerOk = 1;
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
                    else if(strncmp(je->request->sip_method, "BYE", 4) != 0){
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
                    osip_message_t *ack=NULL;
                    p28181Params->call_id = je->cid;
                    p28181Params->dialog_id = je->did;
                    printf("call answered method:%s, call_id:%d, dialog_id:%d\n", je->request->sip_method, 
                                            p28181Params->call_id, p28181Params->dialog_id);
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

int init_udpsocket(int port, struct sockaddr_in *servaddr, char *mcast_addr) {
    int err = -1;
    int socket_fd;                                      
    
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);    
    if (socket_fd < 0 ) {
        APP_ERR("socket failed, port:%d", port);
        return -1;
    }  
   
    memset(servaddr, 0, sizeof(struct sockaddr_in));
    servaddr->sin_family 	   = AF_INET;
    servaddr->sin_addr.s_addr  = htonl(INADDR_ANY);
    servaddr->sin_port 		   = htons(port);
   
    err = bind(socket_fd,(struct sockaddr*)servaddr, sizeof(struct sockaddr_in)) ;
    if(err < 0) {
        APP_ERR("bind failed, port:%d", port);
        return -2;
    }
     
    /*set enable MULTICAST LOOP */                                       
    int loop = 1;
    err = setsockopt(socket_fd,IPPROTO_IP, IP_MULTICAST_LOOP,&loop, sizeof(loop));
    if(err < 0) {
        APP_ERR("setsockopt IP_MULTICAST_LOOP failed, port:%d", port);
        return -3;
    }
   
    return socket_fd;
}

void release_udpsocket(int socket_fd, char *mcast_addr) {
    close(socket_fd);
}

int inline ProgramStreamPackHeader(char* Pack, int length, char **NextPack, int *leftlength) {
    //printf("[%s]%x %x %x %x\n", __FUNCTION__, Pack[0], Pack[1], Pack[2], Pack[3]);
    //通过 00 00 01 ba头的第14个字节的最后3位来确定头部填充了多少字节
    program_stream_pack_header *PsHead = (program_stream_pack_header *)Pack;
    unsigned char pack_stuffing_length = PsHead->stuffinglen & '\x07';

    *leftlength = length - sizeof(program_stream_pack_header) - pack_stuffing_length;//减去头和填充的字节
    *NextPack = Pack+sizeof(program_stream_pack_header) + pack_stuffing_length;
    if(*leftlength<4) return 0;

    return *leftlength;
}

inline int ProgramStreamMap(char* Pack, int length, char **NextPack, int *leftlength, char **PayloadData, int *PayloadDataLen)
{
    program_stream_map* PSMPack = (program_stream_map*)Pack;

    //no payload
    *PayloadData = 0;
    *PayloadDataLen = 0;
    
    if((unsigned int)length < sizeof(program_stream_map)) return 0;

    littel_endian_size psm_length;
    psm_length.byte[0] = PSMPack->PackLength.byte[1];
    psm_length.byte[1] = PSMPack->PackLength.byte[0];

    *leftlength = length - psm_length.length - sizeof(program_stream_map);
    if(*leftlength<=0) return 0;

    *NextPack = Pack + psm_length.length + sizeof(program_stream_map);

    return *leftlength;
}

inline int ProgramShHead(char* Pack, int length, char **NextPack, int *leftlength, char **PayloadData, int *PayloadDataLen) {
    program_stream_map* PSMPack = (program_stream_map*)Pack;

    //no payload
    *PayloadData = 0;
    *PayloadDataLen = 0;
    
    if((unsigned int)length < sizeof(program_stream_map)) return 0;

    littel_endian_size psm_length;
    psm_length.byte[0] = PSMPack->PackLength.byte[1];
    psm_length.byte[1] = PSMPack->PackLength.byte[0];

    *leftlength = length - psm_length.length - sizeof(program_stream_map);
    if(*leftlength<=0) return 0;

    *NextPack = Pack + psm_length.length + sizeof(program_stream_map);

    return *leftlength;
}

inline int Pes(char* Pack, int length, char **NextPack, int *leftlength, char **PayloadData, int *PayloadDataLen)
{
    program_stream_e* PSEPack = (program_stream_e*)Pack;

    *PayloadData = 0;
    *PayloadDataLen = 0;

    if((unsigned int)length < sizeof(program_stream_e)) return 0;
    
    littel_endian_size pse_length;
    pse_length.byte[0] = PSEPack->PackLength.byte[1];
    pse_length.byte[1] = PSEPack->PackLength.byte[0];

    *PayloadDataLen = pse_length.length - 2 - 1 - PSEPack->stuffing_length;
    if(*PayloadDataLen>0) 
        *PayloadData = Pack + sizeof(program_stream_e) + PSEPack->stuffing_length;

    *leftlength = length - pse_length.length - sizeof(pack_start_code) - sizeof(littel_endian_size);
    if(*leftlength<=0) return 0;

    *NextPack = Pack + sizeof(pack_start_code) + sizeof(littel_endian_size) + pse_length.length;

    return *leftlength;
}

int inline GetH246FromPs(char* buffer,int length, char *h264Buffer, int *h264length, char *sipId) {
    int leftlength = 0;
    char *NextPack = 0;

    *h264length = 0;

    if(ProgramStreamPackHeader(buffer, length, &NextPack, &leftlength)==0)
        return 0;

    char *PayloadData=NULL; 
    int PayloadDataLen=0;

    while((unsigned int)leftlength >= sizeof(pack_start_code)) {
        PayloadData=NULL;
        PayloadDataLen=0;
        
        if(NextPack 
        && NextPack[0]=='\x00' 
        && NextPack[1]=='\x00' 
        && NextPack[2]=='\x01' 
        && NextPack[3]=='\xE0') {
            //接着就是流包，说明是非i帧
            if(Pes(NextPack, leftlength, &NextPack, &leftlength, &PayloadData, &PayloadDataLen)) {
                if(PayloadDataLen) {
                    if(PayloadDataLen + *h264length < H264_FRAME_SIZE_MAX) {
                        memcpy(h264Buffer, PayloadData, PayloadDataLen);
                        h264Buffer += PayloadDataLen;
                        *h264length += PayloadDataLen;
                    }
                    else {
                        APP_WARRING("h264 frame size exception!! %d:%d", PayloadDataLen, *h264length);
                    }
                }
            }
            else {
                if(PayloadDataLen) {
                    if(PayloadDataLen + *h264length < H264_FRAME_SIZE_MAX) {
                        memcpy(h264Buffer, PayloadData, PayloadDataLen);
                        h264Buffer += PayloadDataLen;
                        *h264length += PayloadDataLen;
                    }
                    else {
                        APP_WARRING("h264 frame size exception!! %d:%d", PayloadDataLen, *h264length);
                    }
                }
                break;
            }
        }
        else if(NextPack 
            && NextPack[0]=='\x00' 
            && NextPack[1]=='\x00'
            && NextPack[2]=='\x01'
            && NextPack[3]=='\xBB') {
            if(ProgramShHead(NextPack, leftlength, &NextPack, &leftlength, &PayloadData, &PayloadDataLen)==0)
                break;
        }
        else if(NextPack 
            && NextPack[0]=='\x00' 
            && NextPack[1]=='\x00'
            && NextPack[2]=='\x01'
            && NextPack[3]=='\xBC') {
            if(ProgramStreamMap(NextPack, leftlength, &NextPack, &leftlength, &PayloadData, &PayloadDataLen)==0)
                break;
        }
        else if(NextPack 
            && NextPack[0]=='\x00' 
            && NextPack[1]=='\x00'
            && NextPack[2]=='\x01'
            && (NextPack[3]=='\xC0' || NextPack[3]=='\xBD')) {
            //printf("audio ps frame, skip it\n");
            break;
        }
        else {
            printf("[%s]no know %x %x %x %x\n", sipId, NextPack[0], NextPack[1], NextPack[2], NextPack[3]);
            break;
        }
    }
    
    return *h264length;
}

static void *rtp_recv_thread(void *arg) {
    int socket_fd;
    CameraParams *p = (CameraParams *)arg;
    int rtp_port = p->recvPort;
    struct sockaddr_in servaddr;

    socket_fd = init_udpsocket(rtp_port, &servaddr, NULL);
    if(socket_fd >= 0) {
        //printf("start socket port %d success\n", rtp_port);
    }

    unsigned char *buf = (unsigned char *)malloc(RTP_MAXBUF);
    if(buf == NULL) {
        APP_ERR("malloc failed buf");
        return NULL;
    }
    unsigned char *psBuf = (unsigned char *)malloc(PS_BUF_SIZE);
    if(psBuf == NULL) {
        APP_ERR("malloc failed");
        return NULL;
    }
    char *h264buf = (char *)malloc(H264_FRAME_SIZE_MAX);
    if(h264buf == NULL) {
        APP_ERR("malloc failed");
        return NULL;
    }
    int recvLen;
    int addr_len = sizeof(struct sockaddr_in);                                                        
    int rtpHeadLen = sizeof(RTP_header_t);

    char filename[128];
    snprintf(filename, 128, "%s.264", p->sipId);
    p->fpH264 = fopen(filename, "wb");
    if(p->fpH264 == NULL) {
        APP_ERR("fopen %s failed", filename);
        return NULL;
    }

    APP_DEBUG("%s:%d starting ...", p->sipId, p->recvPort);

    int cnt = 0;
    int rtpPsLen, h264length, psLen = 0;
    unsigned char *ptr;
    memset(buf, 0, RTP_MAXBUF); 
    while(p->running) {
        recvLen = recvfrom(socket_fd, buf, RTP_MAXBUF, 0, (struct sockaddr*)&servaddr, (socklen_t*)&addr_len);
        if(recvLen > rtpHeadLen) {
            ptr = psBuf + psLen;
            rtpPsLen = recvLen - rtpHeadLen;
            if(psLen + rtpPsLen < PS_BUF_SIZE) {
                memcpy(ptr, buf + rtpHeadLen, rtpPsLen);
            }
            else {
                APP_WARRING("psBuf memory overflow, %d\n", psLen + rtpPsLen);
                psLen = 0;
                continue;
            }
            if(ptr[0] == 0x00 && ptr[1] == 0x00 && ptr[2] == 0x01 && ptr[3] == 0xBA && psLen > 0) {
                if(cnt % 10000 == 0) {
                    printf("rtpRecvPort:%d, cnt:%d, pssize:%d\n", rtp_port, cnt ++, psLen);
                }
                if(cnt % 25 == 0) {
                    p->status = 1;
                }
                GetH246FromPs((char *)psBuf, psLen, h264buf, &h264length, p->sipId);
                if(h264length > 0) {
                    fwrite(h264buf, 1, h264length, p->fpH264);
                }
                memcpy(psBuf, ptr, rtpPsLen);
                psLen = 0;
                cnt ++;
            }
            psLen += rtpPsLen;
        }
        else {
            perror("recvfrom()");
        }

        if(recvLen > 1500) {
            printf("udp frame exception, %d\n", recvLen);
        }
    }

    release_udpsocket(socket_fd, NULL);	
    if(buf != NULL) {
        free(buf);
    }
    if(psBuf != NULL) {
        free(psBuf);
    }
    if(h264buf != NULL) {
        free(h264buf);
    }
    if(p->fpH264 != NULL) {
        fclose(p->fpH264);
        p->fpH264 = NULL;
    }

    APP_DEBUG("%s:%d run over", p->sipId, p->recvPort);

    return NULL;
}

static void *stream_keep_alive_thread(void *arg) {
    int socket_fd;
    CameraParams *p = (CameraParams *)arg;
    int rtcp_port = p->recvPort + 1;
    struct sockaddr_in servaddr;
    struct timeval tv;

    socket_fd = init_udpsocket(rtcp_port, &servaddr, NULL);
    if(socket_fd >= 0) {
        //printf("start socket port %d success\n", rtcp_port);
    }

    unsigned char *buf = (unsigned char *)malloc(1024);
    if(buf == NULL) {
        APP_ERR("malloc failed buf");
        return NULL;
    }
    int recvLen;
    int addr_len = sizeof(struct sockaddr_in);                                                        

    APP_DEBUG("%s:%d starting ...", p->sipId, rtcp_port);

    memset(buf, 0, 1024); 
    while(p->running) {
        recvLen = recvfrom(socket_fd, buf, 1024, 0, (struct sockaddr*)&servaddr, (socklen_t*)&addr_len);
        if(recvLen > 0) {
            //printf("stream_keep_alive_thread, rtcp_port %d, recv %d bytes\n", rtcp_port, recvLen);
            recvLen = sendto(socket_fd, buf, recvLen, 0, (struct sockaddr*)&servaddr, sizeof(struct sockaddr_in));
            if(recvLen <= 0) {
                APP_ERR("sendto %d failed", rtcp_port);
            }
        }
        else {
            perror("recvfrom()");
        }
        gettimeofday(&tv, NULL);
    }

    release_udpsocket(socket_fd, NULL);	
    if(buf != NULL) {
        free(buf);
    }

    APP_DEBUG("%s:%d run over", p->sipId, rtcp_port);

    return NULL;
}

static int startStreamRecv(liveVideoStreamParams *pliveVideoParams) {
    int i;
    pthread_t pid;
    CameraParams *p;

    for(i = 0; i < pliveVideoParams->cameraNum; i ++) {
        p = pliveVideoParams->pCameraParams + i;
        p->statusErrCnt = 0;
        p->running = 1;
        if(pthread_create(&pid, NULL, rtp_recv_thread, p) != 0) {
            APP_ERR("pthread_create rtp_recv_thread err, %s:%d", p->sipId, p->recvPort);
        }
        else {
            pthread_detach(pid);
        }
        if(pthread_create(&pid, NULL, stream_keep_alive_thread, p) != 0) {
            APP_ERR("pthread_create stream_keep_alive_thread err, %s:%d", p->sipId, p->recvPort + 1);
        }
        else {
            pthread_detach(pid);
        }
    }

    return 0;
}

static void *gb28181ServerThread(void *arg) {
    int iReturnCode = 0;
    struct eXosip_t *eCtx;
    gb28181Params *p28181Params = (gb28181Params *)(arg);

    eCtx = eXosip_malloc();
    iReturnCode = eXosip_init (eCtx);
    if (iReturnCode != OSIP_SUCCESS ) {
        APP_ERR("Can't initialize eXosip!");
        return NULL;
    }
    else {
        printf("eXosip_init successfully!\n");
    }

    iReturnCode = eXosip_listen_addr (eCtx, IPPROTO_UDP, NULL, p28181Params->localSipPort, AF_INET, 0);
    if(iReturnCode !=  OSIP_SUCCESS) {
        APP_ERR("eXosip_listen_addr error!");
        return NULL;
    }

    p28181Params->eCtx = eCtx;
    MainProcess(p28181Params, eCtx);

    eXosip_quit(eCtx);
    osip_free(eCtx);
    eCtx = NULL;
    p28181Params->eCtx = NULL;

    APP_DEBUG("%s run over", __func__);

    return 0;
}

static int sendInvitePlay(char *playSipId, int rtp_recv_port, gb28181Params *p28181Params) {
    char dest_call[256], source_call[256], subject[128];
    osip_message_t *invite=NULL;
    int ret;
    struct eXosip_t *peCtx = p28181Params->eCtx;

    snprintf(dest_call, 256, "sip:%s@%s:%d", playSipId, p28181Params->platformIpAddr, p28181Params->platformSipPort);
    snprintf(source_call, 256, "sip:%s@%s", p28181Params->localSipId, p28181Params->localIpAddr);
    snprintf(subject, 128, "%s:0,%s:0", playSipId, p28181Params->localSipId);
    ret = eXosip_call_build_initial_invite(peCtx, &invite, dest_call, source_call, NULL, subject);
    if(ret != 0) {
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
                "a=recvonly\r\n", playSipId, p28181Params->localIpAddr,
                                    p28181Params->localIpAddr, rtp_recv_port);
    osip_message_set_body(invite, body, bodyLen);
    osip_message_set_content_type(invite, "APPLICATION/SDP");
    eXosip_lock(peCtx);
    eXosip_call_send_initial_invite(peCtx, invite);
    eXosip_unlock(peCtx);

    return 0;
}

static int sendPlayBye(gb28181Params *p28181Params) {
    struct eXosip_t *peCtx = p28181Params->eCtx;

    eXosip_lock(peCtx);
    eXosip_call_terminate(peCtx, p28181Params->call_id, p28181Params->dialog_id);
    eXosip_unlock(peCtx);
    
    return 0;
}

static int startCameraRealStream(liveVideoStreamParams *pliveVideoParams) {
    int i;
    CameraParams *p;

    for(i = 0; i < pliveVideoParams->cameraNum; i ++) {
        p = pliveVideoParams->pCameraParams + i;
        sendInvitePlay(p->sipId, p->recvPort, &(pliveVideoParams->gb28181Param));
    }

    return 0;
}

//TODO : save call_id and dialog_id for play bye?
static int stopCameraRealStream(liveVideoStreamParams *pliveVideoParams) {
    int i, tryCnt;
    CameraParams *p;
    gb28181Params *p28181Params = &(pliveVideoParams->gb28181Param);

    for(i = 0; i < pliveVideoParams->cameraNum; i ++) {
        p = pliveVideoParams->pCameraParams + i;
        p28181Params->call_id = -1;
        sendInvitePlay(p->sipId, p->recvPort, p28181Params);
        tryCnt = 10;
        while(tryCnt-- > 0) {
            if(p28181Params->call_id != -1) {
                break;
            }
            usleep(100000);
        }
        if(p28181Params->call_id == -1) {
            APP_WARRING("exception wait call_id:%d, %s", p28181Params->call_id, p->sipId);
        }
        sendPlayBye(p28181Params);

        p->running = 0;
    }

    return 0;
}

static int checkCameraStatus(liveVideoStreamParams *pliveVideoParams) {
    int i;
    CameraParams *p;
    gb28181Params *p28181Params = &(pliveVideoParams->gb28181Param);

    for(i = 0; i < pliveVideoParams->cameraNum; i ++) {
        p = pliveVideoParams->pCameraParams + i;
        if(p->status == 0) {
            p->statusErrCnt ++;
            if(p->statusErrCnt % 10 == 0) {
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

static int stopStreamRecv(liveVideoStreamParams *pliveVideoParams) {
    int i;
    CameraParams *p;

    for(i = 0; i < pliveVideoParams->cameraNum; i ++) {
        p = pliveVideoParams->pCameraParams + i;
        p->running = 0;
    }

    return 0;
}

const char *whitespace_cb(mxml_node_t *node, int where) {
    return NULL;
}

static int sendQueryCatalog(gb28181Params *p28181Params) {
    char sn[32];
    int ret;
    mxml_node_t *tree, *query, *node;
    struct eXosip_t *peCtx = p28181Params->eCtx;
    char *deviceId = p28181Params->platformSipId;

    tree = mxmlNewXML("1.0");
    if(tree != NULL) {
        query = mxmlNewElement(tree, "Query");
        if(query != NULL) {
            char buf[256] = {0};
            char dest_call[256], source_call[256];
            node = mxmlNewElement(query, "CmdType");
            mxmlNewText(node, 0, "Catalog");
            node = mxmlNewElement(query, "SN");
            snprintf(sn, 32, "%d", p28181Params->SN++);
            mxmlNewText(node, 0, sn);
            node = mxmlNewElement(query, "DeviceID");
            mxmlNewText(node, 0, deviceId);
            mxmlSaveString(tree, buf, 256, whitespace_cb);
            //printf("send query catalog:%s\n", buf);
            osip_message_t *message = NULL;
            snprintf(dest_call, 256, "sip:%s@%s:%d", p28181Params->platformSipId, 
                    p28181Params->platformIpAddr, p28181Params->platformSipPort);
            snprintf(source_call, 256, "sip:%s@%s", p28181Params->localSipId, p28181Params->localIpAddr);
            ret = eXosip_message_build_request(peCtx, &message, "MESSAGE", dest_call, source_call, NULL);
            if(ret == 0 && message != NULL) {
                osip_message_set_body(message, buf, strlen(buf));
                osip_message_set_content_type(message,"Application/MANSCDP+xml");
                eXosip_lock(peCtx);
                eXosip_message_send_request(peCtx, message);
                eXosip_unlock(peCtx);
                APP_DEBUG("xml:%s, dest_call:%s, source_call:%s, ok", buf, dest_call, source_call);
            }
            else {
                APP_ERR("eXosip_message_build_request failed");
            }
        }
        else {
            APP_ERR("mxmlNewElement Query failed");
        }
        mxmlDelete(tree);
    }
    else {
        APP_ERR("mxmlNewXML failed");
    }

    return 0;
}

int main(int argc, char *argv[]) {
    pthread_t pid;
    APP_DEBUG("Built: %s %s, liveVideoStream starting ...", __TIME__, __DATE__);

    initParams((char *)GB28181_CFG_FILE);
    g_liveVideoParams.running = 1;
    g_liveVideoParams.gb28181Param.running = 1;
    if(pthread_create(&pid, NULL, gb28181ServerThread, &(g_liveVideoParams.gb28181Param)) != 0) {
        APP_ERR("pthread_create gb28181ServerThread err");
    }
    else {
        pthread_detach(pid);
    }

	int tmpCnt = 20;
    while((!g_liveVideoParams.gb28181Param.registerOk) && (tmpCnt > 0)) {
        printf("waiting register %d...\n", tmpCnt --);
        sleep(1);
    }
    sendQueryCatalog(&(g_liveVideoParams.gb28181Param));

    startStreamRecv(&g_liveVideoParams);
    sleep(1);
    startCameraRealStream(&g_liveVideoParams);

    while(g_liveVideoParams.running) {
        checkCameraStatus(&g_liveVideoParams);
        sleep(2);
    }

    g_liveVideoParams.running = 0;
    stopCameraRealStream(&g_liveVideoParams);
    usleep(300000);
    stopStreamRecv(&g_liveVideoParams);
    g_liveVideoParams.gb28181Param.running = 0;
    sleep(1);
    APP_DEBUG("liveVideoStream run over");

    return 0;
}

