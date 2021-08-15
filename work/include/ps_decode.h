
int inline ProgramStreamPackHeader(char* Pack, int length, char** NextPack, int* leftlength) {
    //printf("[%s]%x %x %x %x\n", __FUNCTION__, Pack[0], Pack[1], Pack[2], Pack[3]);
    //通过 00 00 01 ba头的第14个字节的最后3位来确定头部填充了多少字节
    program_stream_pack_header* PsHead = (program_stream_pack_header*)Pack;
    unsigned char pack_stuffing_length = PsHead->stuffinglen & '\x07';

    *leftlength = length - sizeof(program_stream_pack_header) - pack_stuffing_length;//减去头和填充的字节
    *NextPack = Pack + sizeof(program_stream_pack_header) + pack_stuffing_length;
    if (*leftlength < 4) return 0;

    return *leftlength;
}

inline int ProgramStreamMap(char* Pack, int length, char** NextPack, int* leftlength, char** PayloadData, int* PayloadDataLen)
{
    program_stream_map* PSMPack = (program_stream_map*)Pack;

    //no payload
    *PayloadData = 0;
    *PayloadDataLen = 0;

    if ((unsigned int)length < sizeof(program_stream_map)) return 0;

    littel_endian_size psm_length;
    psm_length.byte[0] = PSMPack->PackLength.byte[1];
    psm_length.byte[1] = PSMPack->PackLength.byte[0];

    *leftlength = length - psm_length.length - sizeof(program_stream_map);
    if (*leftlength <= 0) return 0;

    *NextPack = Pack + psm_length.length + sizeof(program_stream_map);

    return *leftlength;
}

inline int ProgramShHead(char* Pack, int length, char** NextPack, int* leftlength, char** PayloadData, int* PayloadDataLen) {
    program_stream_map* PSMPack = (program_stream_map*)Pack;

    //no payload
    *PayloadData = 0;
    *PayloadDataLen = 0;

    if ((unsigned int)length < sizeof(program_stream_map)) return 0;

    littel_endian_size psm_length;
    psm_length.byte[0] = PSMPack->PackLength.byte[1];
    psm_length.byte[1] = PSMPack->PackLength.byte[0];

    *leftlength = length - psm_length.length - sizeof(program_stream_map);
    if (*leftlength <= 0) return 0;

    *NextPack = Pack + psm_length.length + sizeof(program_stream_map);

    return *leftlength;
}

inline int Pes(char* Pack, int length, char** NextPack, int* leftlength, char** PayloadData, int* PayloadDataLen)
{
    program_stream_e* PSEPack = (program_stream_e*)Pack;

    *PayloadData = 0;
    *PayloadDataLen = 0;

    if ((unsigned int)length < sizeof(program_stream_e)) return 0;

    littel_endian_size pse_length;
    pse_length.byte[0] = PSEPack->PackLength.byte[1];
    pse_length.byte[1] = PSEPack->PackLength.byte[0];

    *PayloadDataLen = pse_length.length - 2 - 1 - PSEPack->stuffing_length;
    if (*PayloadDataLen > 0)
        *PayloadData = Pack + sizeof(program_stream_e) + PSEPack->stuffing_length;

    *leftlength = length - pse_length.length - sizeof(pack_start_code) - sizeof(littel_endian_size);
    if (*leftlength <= 0) return 0;

    *NextPack = Pack + sizeof(pack_start_code) + sizeof(littel_endian_size) + pse_length.length;

    return *leftlength;
}

int inline GetH246FromPs(char* buffer, int length, char* h264Buffer, int* h264length, char* sipId) {
    int leftlength = 0;
    char* NextPack = 0;

    *h264length = 0;

    if (ProgramStreamPackHeader(buffer, length, &NextPack, &leftlength) == 0)
        return 0;

    char* PayloadData = NULL;
    int PayloadDataLen = 0;

    while ((unsigned int)leftlength >= sizeof(pack_start_code)) {
        PayloadData = NULL;
        PayloadDataLen = 0;

        if (NextPack
            && NextPack[0] == '\x00'
            && NextPack[1] == '\x00'
            && NextPack[2] == '\x01'
            && NextPack[3] == '\xE0') {
            //接着就是流包，说明是非i帧
            if (Pes(NextPack, leftlength, &NextPack, &leftlength, &PayloadData, &PayloadDataLen)) {
                if (PayloadDataLen) {
                    if (PayloadDataLen + *h264length < H264_FRAME_SIZE_MAX) {
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
                if (PayloadDataLen) {
                    if (PayloadDataLen + *h264length < H264_FRAME_SIZE_MAX) {
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
        else if (NextPack
            && NextPack[0] == '\x00'
            && NextPack[1] == '\x00'
            && NextPack[2] == '\x01'
            && NextPack[3] == '\xBB') {
            if (ProgramShHead(NextPack, leftlength, &NextPack, &leftlength, &PayloadData, &PayloadDataLen) == 0)
                break;
        }
        else if (NextPack
            && NextPack[0] == '\x00'
            && NextPack[1] == '\x00'
            && NextPack[2] == '\x01'
            && NextPack[3] == '\xBC') {
            if (ProgramStreamMap(NextPack, leftlength, &NextPack, &leftlength, &PayloadData, &PayloadDataLen) == 0)
                break;
        }
        else if (NextPack
            && NextPack[0] == '\x00'
            && NextPack[1] == '\x00'
            && NextPack[2] == '\x01'
            && (NextPack[3] == '\xC0' || NextPack[3] == '\xBD')) {
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
