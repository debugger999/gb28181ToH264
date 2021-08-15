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

#include "ps_decode.h"
#include "sip_server.h"

#include <map>
#include <string>

LocalPlatform g_LocalPlatform;
std::map<std::string, gb28181Params*> g_nvrid2nvrptr;



static int doParaseJson(char* buf)
{
    cJSON* root = cJSON_Parse(buf);

    // local
    cJSON* pSub = cJSON_GetObjectItem(root, "local_id");
    if (pSub != NULL) {
        APP_DEBUG("local_id:%s", pSub->valuestring);
        strncpy(g_LocalPlatform.localSipId, pSub->valuestring, 256);
    }
    pSub = cJSON_GetObjectItem(root, "local_port");
    if (pSub != NULL) {
        APP_DEBUG("local_port:%d", pSub->valueint);
        g_LocalPlatform.localSipPort = pSub->valueint;
    }
    pSub = cJSON_GetObjectItem(root, "local_ip");
    if (pSub != NULL) {
        APP_DEBUG("local_ip:%s", pSub->valuestring);
        strncpy(g_LocalPlatform.localIpAddr, pSub->valuestring, 128);
    }

    // nvr_platform
    if (root != NULL) {
        cJSON* pSubRoot = cJSON_GetObjectItem(root, "nvr_platform");
        if (pSubRoot != NULL) {
            int nvr_size = cJSON_GetArraySize(pSubRoot);
            g_LocalPlatform.liveNvrNums = nvr_size;
            for (int i = 0; i < nvr_size; i++) {
                cJSON* pnvr = cJSON_GetArrayItem(pSubRoot, i);
                cJSON* pSub = cJSON_GetObjectItem(pnvr, "platform_id");
                if (pSub != NULL) {
                    APP_DEBUG("platform_id:%s", pSub->valuestring);
                    strncpy(g_LocalPlatform.liveVideo[i].gb28181Param.platformSipId, pSub->valuestring, 256);
                }
                pSub = cJSON_GetObjectItem(pnvr, "platform_port");
                if (pSub != NULL) {
                    APP_DEBUG("platform_port:%d", pSub->valueint);
                    g_LocalPlatform.liveVideo[i].gb28181Param.platformSipPort = pSub->valueint;
                }
                pSub = cJSON_GetObjectItem(pnvr, "platform_ip");
                if (pSub != NULL) {
                    APP_DEBUG("platform_ip:%s", pSub->valuestring);
                    strncpy(g_LocalPlatform.liveVideo[i].gb28181Param.platformIpAddr, pSub->valuestring, 128);
                }

                pSub = cJSON_GetObjectItem(pnvr, "camera_num");
                if (pSub != NULL) {
                    APP_DEBUG("camera_num:%d", pSub->valueint);
                    g_LocalPlatform.liveVideo[i].cameraNum = pSub->valueint;
                    if (g_LocalPlatform.liveVideo[i].cameraNum > 0 && g_LocalPlatform.liveVideo[i].cameraNum < CAMERA_SUPPORT_MAX) {
                        g_LocalPlatform.liveVideo[i].pCameraParams = (CameraParams*)malloc(sizeof(CameraParams) * g_LocalPlatform.liveVideo[i].cameraNum);
                        if (g_LocalPlatform.liveVideo[i].pCameraParams == NULL) {
                            APP_ERR("malloc failed");
                            return -1;
                        }
                        memset(g_LocalPlatform.liveVideo[i].pCameraParams, 0, sizeof(CameraParams) * g_LocalPlatform.liveVideo[i].cameraNum);
                        CameraParams* p;
                        char cameraName[32];
                        for (int j = 0; j < g_LocalPlatform.liveVideo[i].cameraNum; j++) {
                            p = g_LocalPlatform.liveVideo[i].pCameraParams + j;
                            snprintf(cameraName, 32, "camera%d_sip_id", j + 1);
                            pSub = cJSON_GetObjectItem(pnvr, cameraName);
                            if (pSub != NULL) {
                                APP_DEBUG("%s:%s", cameraName, pSub->valuestring);
                                strncpy(p->sipId, pSub->valuestring, 256);
                            }
                            else {
                                APP_WARRING("get json failed, %s", cameraName);
                            }
                            snprintf(cameraName, 32, "camera%d_recv_port", j + 1);
                            pSub = cJSON_GetObjectItem(pnvr, cameraName);
                            if (pSub != NULL) {
                                APP_DEBUG("%s:%d", cameraName, pSub->valueint);
                                p->recvPort = pSub->valueint;
                            }
                            else {
                                APP_WARRING("get json failed, %s", cameraName);
                            }
                        }
                    }
                    else {
                        APP_WARRING("err cameraNum : %d", g_LocalPlatform.liveVideo[i].cameraNum);
                    }
                }
            }
        }
        else {
            APP_ERR("err");
        }

        cJSON_Delete(root);
    }
    else {
        APP_ERR("err, buf:%s", buf);
    }

    return 0;
}

static int initParams(char* jsonCfgFile) {
    char* buf = NULL;

    memset(&g_LocalPlatform, 0, sizeof(g_LocalPlatform));
    FILE* fp = fopen(jsonCfgFile, "rb");
    if (fp != NULL) {
        fseek(fp, 0L, SEEK_END);
        int cfgSie = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        buf = (char*)malloc(cfgSie / 1024 * 1024 + 1024);
        if (buf == NULL) {
            APP_ERR("malloc failed");
            goto err;
        }
        if (fread(buf, 1, cfgSie, fp)) {
        }
        doParaseJson(buf);
    }
    else {
        APP_ERR("fopen %s failed", jsonCfgFile);
    }
    for (int i = 0; i < g_LocalPlatform.liveNvrNums; i++) {
        g_LocalPlatform.liveVideo[i].gb28181Param.SN = 1;
        g_LocalPlatform.liveVideo[i].gb28181Param.call_id = -1;
        g_LocalPlatform.liveVideo[i].gb28181Param.dialog_id = -1;
        g_LocalPlatform.liveVideo[i].gb28181Param.registerOk = 0;
        // 保存nvrsip id到nvrgb28181的映射
        g_nvrid2nvrptr[g_LocalPlatform.liveVideo[i].gb28181Param.platformSipId] = &g_LocalPlatform.liveVideo[i].gb28181Param;

    }

err:
    if (buf != NULL) {
        free(buf);
    }
    if (fp != NULL) {
        fclose(fp);
    }

    return 0;
}

static void* rtp_recv_thread(void* arg)
{
    int socket_fd;
    CameraParams* p = (CameraParams*)arg;
    int rtp_port = p->recvPort;
    struct sockaddr_in servaddr;

    socket_fd = init_udpsocket(rtp_port, &servaddr, NULL);
    if (socket_fd >= 0) {
        //printf("start socket port %d success\n", rtp_port);
    }

    unsigned char* buf = (unsigned char*)malloc(RTP_MAXBUF);
    if (buf == NULL) {
        APP_ERR("malloc failed buf");
        return NULL;
    }
    unsigned char* psBuf = (unsigned char*)malloc(PS_BUF_SIZE);
    if (psBuf == NULL) {
        APP_ERR("malloc failed");
        return NULL;
    }
    char* h264buf = (char*)malloc(H264_FRAME_SIZE_MAX);
    if (h264buf == NULL) {
        APP_ERR("malloc failed");
        return NULL;
    }
    int recvLen;
    int addr_len = sizeof(struct sockaddr_in);
    int rtpHeadLen = sizeof(RTP_header_t);

    char filename[128];
    snprintf(filename, 128, "%s.h264", p->sipId);
    p->fpH264 = fopen(filename, "wb");
    if (p->fpH264 == NULL) {
        APP_ERR("fopen %s failed", filename);
        return NULL;
    }

    APP_DEBUG("%s:%d starting ...", p->sipId, p->recvPort);

    int cnt = 0;
    int rtpPsLen, h264length, psLen = 0;
    unsigned char* ps_ptr;
    memset(buf, 0, RTP_MAXBUF);
    RTP_header_t header = { 0 };
    while (p->running) {
        recvLen = recvfrom(socket_fd, buf, RTP_MAXBUF, 0, (struct sockaddr*)&servaddr, (socklen_t*)&addr_len);
        if (recvLen > rtpHeadLen) {
            memcpy(&header, buf, sizeof(RTP_header_t));
            if (header.paytype != 0x60) { // 判断是否为ps协议
                printf("recv paytype is %d\n", header.paytype);
                continue;
            }

            ps_ptr = psBuf + psLen;
            rtpPsLen = recvLen - rtpHeadLen;
            if (psLen + rtpPsLen < PS_BUF_SIZE) {
                // 判断是否为视频：过滤音频
                if (buf[rtpHeadLen + 0] == 0x00 && buf[rtpHeadLen + 1] == 0x00 && buf[rtpHeadLen + 2] == 0x01 && buf[rtpHeadLen + 3] == 0xC0) {
                    APP_WARRING("recv audio：camid:%s seq:%d", p->sipId, header.seq_number);
                    continue;
                }
                APP_DEBUG("recv video：camid:%s seq:%d", p->sipId, header.seq_number);
                memcpy(ps_ptr, buf + rtpHeadLen, rtpPsLen);
            }
            else {
                APP_WARRING("psBuf memory overflow, %d\n", psLen + rtpPsLen);
                psLen = 0;
                continue;
            }
            if (ps_ptr[0] == 0x00 && ps_ptr[1] == 0x00 && ps_ptr[2] == 0x01 && ps_ptr[3] == 0xBA && psLen > 0) { // ps头
                if (cnt % 10000 == 0) {
                    printf("rtpRecvPort:%d, cnt:%d, pssize:%d\n", rtp_port, cnt++, psLen);
                }
                if (cnt % 25 == 0) {
                    p->status = 1;
                }
                GetH246FromPs((char*)psBuf, psLen, h264buf, &h264length, p->sipId);
                if (h264length > 0) {
                    fwrite(h264buf, 1, h264length, p->fpH264);
                }
                memcpy(psBuf, ps_ptr, rtpPsLen);
                psLen = 0;
                cnt++;
            }
            psLen += rtpPsLen;
        }
        else {
            perror("recvfrom()");
        }

        if (recvLen > 1500) {
            printf("udp frame exception, %d\n", recvLen);
        }
    }

    release_udpsocket(socket_fd, NULL);
    if (buf != NULL) {
        free(buf);
    }
    if (psBuf != NULL) {
        free(psBuf);
    }
    if (h264buf != NULL) {
        free(h264buf);
    }
    if (p->fpH264 != NULL) {
        fclose(p->fpH264);
        p->fpH264 = NULL;
    }

    APP_DEBUG("%s:%d run over", p->sipId, p->recvPort);

    return NULL;
}

static void* stream_keep_alive_thread(void* arg) {
    int socket_fd;
    CameraParams* p = (CameraParams*)arg;
    int rtcp_port = p->recvPort + 1;
    struct sockaddr_in servaddr;
    struct timeval tv;

    socket_fd = init_udpsocket(rtcp_port, &servaddr, NULL);
    if (socket_fd >= 0) {
        //printf("start socket port %d success\n", rtcp_port);
    }

    unsigned char* buf = (unsigned char*)malloc(1024);
    if (buf == NULL) {
        APP_ERR("malloc failed buf");
        return NULL;
    }
    int recvLen;
    int addr_len = sizeof(struct sockaddr_in);

    APP_DEBUG("%s:%d starting ...", p->sipId, rtcp_port);

    memset(buf, 0, 1024);
    while (p->running) {
        recvLen = recvfrom(socket_fd, buf, 1024, 0, (struct sockaddr*)&servaddr, (socklen_t*)&addr_len);
        if (recvLen > 0) {
            //printf("stream_keep_alive_thread, rtcp_port %d, recv %d bytes\n", rtcp_port, recvLen);
            recvLen = sendto(socket_fd, buf, recvLen, 0, (struct sockaddr*)&servaddr, sizeof(struct sockaddr_in));
            if (recvLen <= 0) {
                APP_ERR("sendto %d failed", rtcp_port);
            }
        }
        else {
            perror("recvfrom()");
        }
        gettimeofday(&tv, NULL);
    }

    release_udpsocket(socket_fd, NULL);
    if (buf != NULL) {
        free(buf);
    }

    APP_DEBUG("%s:%d run over", p->sipId, rtcp_port);

    return NULL;
}

static int startStreamRecv(liveVideoStreamParams* pliveVideoParams) {
    int i;
    pthread_t pid;
    CameraParams* p;

    for (i = 0; i < pliveVideoParams->cameraNum; i++) {
        p = pliveVideoParams->pCameraParams + i;
        p->statusErrCnt = 0;
        p->running = 1;
        if (pthread_create(&pid, NULL, rtp_recv_thread, p) != 0) {
            APP_ERR("pthread_create rtp_recv_thread err, %s:%d", p->sipId, p->recvPort);
        }
        else {
            pthread_detach(pid);
        }
        if (pthread_create(&pid, NULL, stream_keep_alive_thread, p) != 0) {
            APP_ERR("pthread_create stream_keep_alive_thread err, %s:%d", p->sipId, p->recvPort + 1);
        }
        else {
            pthread_detach(pid);
        }
    }

    return 0;
}


static int startCameraRealStream(liveVideoStreamParams* pliveVideoParams) {
    int i;
    CameraParams* p;

    for (i = 0; i < pliveVideoParams->cameraNum; i++) {
        p = pliveVideoParams->pCameraParams + i;
        sendInvitePlay(p->sipId, p->recvPort, &(pliveVideoParams->gb28181Param));
    }

    return 0;
}

//TODO : save call_id and dialog_id for play bye?
static int stopCameraRealStream(liveVideoStreamParams* pliveVideoParams) {
    int i, tryCnt;
    CameraParams* p;
    gb28181Params* p28181Params = &(pliveVideoParams->gb28181Param);

    for (i = 0; i < pliveVideoParams->cameraNum; i++) {
        p = pliveVideoParams->pCameraParams + i;
        p28181Params->call_id = -1;
        sendInvitePlay(p->sipId, p->recvPort, p28181Params);
        tryCnt = 10;
        while (tryCnt-- > 0) {
            if (p28181Params->call_id != -1) {
                break;
            }
            usleep(100000);
        }
        if (p28181Params->call_id == -1) {
            APP_WARRING("exception wait call_id:%d, %s", p28181Params->call_id, p->sipId);
        }
        sendPlayBye(p28181Params);

        p->running = 0;
    }

    return 0;
}

static int stopStreamRecv(liveVideoStreamParams* pliveVideoParams) {
    int i;
    CameraParams* p;

    for (i = 0; i < pliveVideoParams->cameraNum; i++) {
        p = pliveVideoParams->pCameraParams + i;
        p->running = 0;
    }

    return 0;
}

const char* whitespace_cb(mxml_node_t* node, int where) {
    return NULL;
}

static int sendQueryCatalog(gb28181Params* p28181Params) {
    char sn[32];
    int ret;
    mxml_node_t* tree, * query, * node;
    struct eXosip_t* peCtx = g_LocalPlatform.eCtx;
    char* deviceId = p28181Params->platformSipId;

    tree = mxmlNewXML("1.0");
    if (tree != NULL) {
        query = mxmlNewElement(tree, "Query");
        if (query != NULL) {
            char buf[256] = { 0 };
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
            osip_message_t* message = NULL;
            snprintf(dest_call, 256, "sip:%s@%s:%d", p28181Params->platformSipId,
                p28181Params->platformIpAddr, p28181Params->platformSipPort);
            snprintf(source_call, 256, "sip:%s@%s", g_LocalPlatform.localSipId, g_LocalPlatform.localIpAddr);
            ret = eXosip_message_build_request(peCtx, &message, "MESSAGE", dest_call, source_call, NULL);
            if (ret == 0 && message != NULL) {
                osip_message_set_body(message, buf, strlen(buf));
                osip_message_set_content_type(message, "Application/MANSCDP+xml");
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

int main(int argc, char* argv[])
{
    pthread_t pid;
    APP_DEBUG("Built: %s %s, liveVideoStream starting ...", __TIME__, __DATE__);

    initParams((char*)GB28181_CFG_FILE);
    g_LocalPlatform.running = 1;
    if (pthread_create(&pid, NULL, gb28181ServerThread, &(g_LocalPlatform)) != 0) {
        APP_ERR("pthread_create gb28181ServerThread [] err");
    }
    else {
        pthread_detach(pid);
    }

    for (int i = 0; i < g_LocalPlatform.liveNvrNums; i++) {
        int tmpCnt = 20;
        while ((!g_LocalPlatform.liveVideo[i].gb28181Param.registerOk) && (tmpCnt > 0)) {
            printf("nvr[%s] waiting register %d...\n", g_LocalPlatform.liveVideo[i].gb28181Param.platformSipId, tmpCnt--);
            sleep(1);
        }
        sendQueryCatalog(&(g_LocalPlatform.liveVideo[i].gb28181Param));
        startStreamRecv(&g_LocalPlatform.liveVideo[i]);
        sleep(1);
        startCameraRealStream(&g_LocalPlatform.liveVideo[i]);
    }

    while (g_LocalPlatform.running) {
        for (int i = 0; i < g_LocalPlatform.liveNvrNums; i++) {
            checkCameraStatus(&g_LocalPlatform.liveVideo[i]);
            sleep(2);
        }
    }
    for (int i = 0; i < g_LocalPlatform.liveNvrNums; i++) {
        g_LocalPlatform.liveVideo[i].running = 0;
        stopCameraRealStream(&g_LocalPlatform.liveVideo[i]);
        usleep(300000);
        stopStreamRecv(&g_LocalPlatform.liveVideo[i]);
        g_LocalPlatform.liveVideo[i].running = 0;
    }
    sleep(3);
    APP_DEBUG("liveVideoStream run over");

    return 0;
}

