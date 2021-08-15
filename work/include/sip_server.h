/**
 * @file sip_server.h
 * @brief 
 * @author yanchaodong (yanchaodong@outlook.com)
 * @version 1.0
 * @date 2021-08-15
 * 
 * @copyright Copyright (c) 2021
 * 
 * @par 修改日志:
 */

#ifdef __cplusplus
extern "C" {
#endif

int init_udpsocket(int port, struct sockaddr_in* servaddr, char* mcast_addr);

void release_udpsocket(int socket_fd, char* mcast_addr);

int sendInvitePlay(char* playSipId, int rtp_recv_port, gb28181Params* p28181Params);

int sendPlayBye(gb28181Params* p28181Params);

int checkCameraStatus(liveVideoStreamParams* pliveVideoParams);

void* gb28181ServerThread(void* arg);


#ifdef __cplusplus
}
#endif
