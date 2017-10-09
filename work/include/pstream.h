#ifndef __MEDIA_PSTREAM__H__
#define __MEDIA_PSTREAM__H__

#ifndef uint16_t
typedef unsigned short uint16_t;
#endif
#ifndef uint32_t
typedef unsigned int uint32_t;
#endif

typedef struct RTP_HEADER
{
    uint16_t cc:4;
    uint16_t extbit:1;
    uint16_t padbit:1;
    uint16_t version:2;
    uint16_t paytype:7;  //负载类型
    uint16_t markbit:1;  //1表示前面的包为一个解码单元,0表示当前解码单元未结束
    uint16_t seq_number;  //序号
    uint32_t timestamp; //时间戳
    uint32_t ssrc;  //循环校验码
    //uint32_t csrc[16];
} RTP_header_t;

#pragma pack (1)
typedef union littel_endian_size_s {
    unsigned short int	length;
    unsigned char		byte[2];
} littel_endian_size;

typedef struct pack_start_code_s {
    unsigned char start_code[3];
    unsigned char stream_id[1];
} pack_start_code;

typedef struct program_stream_pack_header_s {
    pack_start_code PackStart;// 4
    unsigned char Buf[9];
    unsigned char stuffinglen;
} program_stream_pack_header;

typedef struct program_stream_map_s {
    pack_start_code PackStart;
    littel_endian_size PackLength;//we mast do exchange
    //program_stream_info_length
    //info
    //elementary_stream_map_length
    //elem
} program_stream_map;

typedef struct program_stream_e_s {
    pack_start_code		PackStart;
    littel_endian_size	PackLength;//we mast do exchange
    char				PackInfo1[2];
    unsigned char		stuffing_length;
} program_stream_e;

#endif //__MEDIA_PSTREAM__H__


