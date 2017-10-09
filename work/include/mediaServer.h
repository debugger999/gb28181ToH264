#ifndef ___MEDIA_SERVER_H__
#define ___MEDIA_SERVER_H__

#define APREFIX_NONE   "\033[0m"
#define APREFIX_RED    "\033[0;31m"
#define APREFIX_GREEN  "\033[0;32m"
#define APREFIX_YELLOW "\033[1;33m"

#define APP_DEBUG(format, args...) printf(APREFIX_GREEN"DEBUG : FILE -> %s, %s, LINE -> %d :"  format APREFIX_NONE"\n", __FILE__, __func__, __LINE__, ## args)
#define APP_WARRING(format, args...) printf(APREFIX_YELLOW"WARRING : FILE -> %s, %s, LINE -> %d :"  format APREFIX_NONE"\n", __FILE__, __func__, __LINE__, ## args)
#define APP_ERR(format, args...) printf(APREFIX_RED"ERR : FILE -> %s, %s, LINE -> %d :"  format APREFIX_NONE"\n", __FILE__, __func__, __LINE__, ## args)

#define GB28181_CFG_FILE        "config.json"
#define CAMERA_SUPPORT_MAX      500
#define RTP_MAXBUF          4096
#define PS_BUF_SIZE         (1024*1024*4)
#define H264_FRAME_SIZE_MAX (1024*1024*2)

typedef struct {
    char platformSipId[256];
    char platformIpAddr[128];
    int platformSipPort;
    char localSipId[256];
    char localIpAddr[128];
    int localSipPort;
    int SN;
    struct eXosip_t *eCtx;
    int call_id;
    int dialog_id;
    int registerOk;
    int running;
} gb28181Params;

typedef struct {
    char sipId[256];
    int recvPort;
    int status;
    int statusErrCnt;
    FILE *fpH264;
    int running;
} CameraParams;

typedef struct {
    int cameraNum;
    CameraParams *pCameraParams;
    gb28181Params gb28181Param;
    int stream_input_type;
    int running;
} liveVideoStreamParams;

#endif

