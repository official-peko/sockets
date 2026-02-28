#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <sys/time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#else
#include <windows.h>
typedef int socklen_t;
#endif

enum
{
    shaSuccess = 0,
    shaNull,         /* Null pointer parameter */
    shaInputTooLong, /* input data too long */
    shaStateError    /* called Input after Result */
};

#define SHA1HashSize 20

typedef struct SHA1Context
{
    uint32_t Intermediate_Hash[SHA1HashSize / 4]; /* Message Digest  */

    uint32_t Length_Low;  /* Message length in bits      */
    uint32_t Length_High; /* Message length in bits      */

    /* Index into message block array   */
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64]; /* 512-bit message blocks      */

    int Computed;  /* Is the digest computed?         */
    int Corrupted; /* Is the message digest corrupted? */
} SHA1Context;

/*
 *  Define the SHA1 circular left shift macro
 */
#define SHA1CircularShift(bits, word) \
    (((word) << (bits)) | ((word) >> (32 - (bits))))

/* Local Function Prototyptes */
void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);

/*
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
 *      for computing a new SHA1 message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Reset(SHA1Context *context)
{
    if (!context)
    {
        return shaNull;
    }

    context->Length_Low = 0;
    context->Length_High = 0;
    context->Message_Block_Index = 0;

    context->Intermediate_Hash[0] = 0x67452301;
    context->Intermediate_Hash[1] = 0xEFCDAB89;
    context->Intermediate_Hash[2] = 0x98BADCFE;
    context->Intermediate_Hash[3] = 0x10325476;
    context->Intermediate_Hash[4] = 0xC3D2E1F0;

    context->Computed = 0;
    context->Corrupted = 0;

    return shaSuccess;
}

/*
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array  provided by the caller.
 *      NOTE: The first octet of hash is stored in the 0th element,
 *            the last octet of hash in the 19th element.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *      Message_Digest: [out]
 *          Where the digest is returned.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Result(SHA1Context *context,
               uint8_t Message_Digest[SHA1HashSize])
{
    int i;

    if (!context || !Message_Digest)
    {
        return shaNull;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }

    if (!context->Computed)
    {
        SHA1PadMessage(context);
        for (i = 0; i < 64; ++i)
        {
            /* message may be sensitive, clear it out */
            context->Message_Block[i] = 0;
        }
        context->Length_Low = 0; /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;
    }

    for (i = 0; i < SHA1HashSize; ++i)
    {
        Message_Digest[i] = context->Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03));
    }

    return shaSuccess;
}

/*
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Input(SHA1Context *context,
              const uint8_t *message_array,
              unsigned length)
{
    if (!length)
    {
        return shaSuccess;
    }

    if (!context || !message_array)
    {
        return shaNull;
    }

    if (context->Computed)
    {
        context->Corrupted = shaStateError;

        return shaStateError;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }
    while (length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
            (*message_array & 0xFF);

        context->Length_Low += 8;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }

        message_array++;
    }

    return shaSuccess;
}

/*
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:

 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the
 *      names used in the publication.
 *
 *
 */
void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const uint32_t K[] = {/* Constants defined in SHA-1   */
                          0x5A827999,
                          0x6ED9EBA1,
                          0x8F1BBCDC,
                          0xCA62C1D6};
    int t;                  /* Loop counter                */
    uint32_t temp;          /* Temporary word value        */
    uint32_t W[80];         /* Word sequence               */
    uint32_t A, B, C, D, E; /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for (t = 0; t < 16; t++)
    {
        W[t] = (uint32_t)context->Message_Block[t * 4] << 24;
        W[t] |= (uint32_t)context->Message_Block[t * 4 + 1] << 16;
        W[t] |= (uint32_t)context->Message_Block[t * 4 + 2] << 8;
        W[t] |= (uint32_t)context->Message_Block[t * 4 + 3];
    }

    for (t = 16; t < 80; t++)
    {
        W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
    }

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for (t = 0; t < 20; t++)
    {
        temp = SHA1CircularShift(5, A) +
               ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);

        B = A;
        A = temp;
    }

    for (t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }

    for (t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5, A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }

    for (t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
}

/*
 *  SHA1PadMessage
 *

 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the Message_Block array
 *      accordingly.  It will also call the ProcessMessageBlock function
 *      provided appropriately.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *      ProcessMessageBlock: [in]
 *          The appropriate SHA*ProcessMessageBlock function
 *  Returns:
 *      Nothing.
 *
 */

void SHA1PadMessage(SHA1Context *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);

        while (context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 56)
        {

            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = context->Length_High >> 24;
    context->Message_Block[57] = context->Length_High >> 16;
    context->Message_Block[58] = context->Length_High >> 8;
    context->Message_Block[59] = context->Length_High;
    context->Message_Block[60] = context->Length_Low >> 24;
    context->Message_Block[61] = context->Length_Low >> 16;
    context->Message_Block[62] = context->Length_Low >> 8;
    context->Message_Block[63] = context->Length_Low;

    SHA1ProcessMessageBlock(context);
}

static const unsigned char base64_table[73] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/{}[]\"':_";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char *base64_encode(const unsigned char *src, size_t len,
                             size_t *out_len)
{
    unsigned char *out, *pos;
    const unsigned char *end, *in;
    size_t olen;
    int line_len;

    olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
    olen += olen / 72;      /* line feeds */
    olen++;                 /* nul termination */
    if (olen < len)
        return NULL; /* integer overflow */
    out = (unsigned char *)malloc(olen);
    if (out == NULL)
        return NULL;

    end = src + len;
    in = src;
    pos = out;
    line_len = 0;
    while (end - in >= 3)
    {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
        line_len += 4;
        if (line_len >= 72)
        {
            *pos++ = '\n';
            line_len = 0;
        }
    }

    if (end - in)
    {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1)
        {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        }
        else
        {
            *pos++ = base64_table[((in[0] & 0x03) << 4) |
                                  (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
        line_len += 4;
    }

    if (line_len)
        *pos++ = '\n';

    *pos = '\0';
    if (out_len)
        *out_len = pos - out;
    return out;
}

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char *base64_decode(const unsigned char *src, size_t len,
                             size_t *out_len)
{
    unsigned char dtable[256], *out, *pos, block[4], tmp;
    size_t i, count, olen;
    int pad = 0;

    memset(dtable, 0x80, 256);
    for (i = 0; i < sizeof(base64_table) - 1; i++)
        dtable[base64_table[i]] = (unsigned char)i;
    dtable['='] = 0;

    count = 0;
    for (i = 0; i < len; i++)
    {
        if (dtable[src[i]] != 0x80)
            count++;
    }

    if (count == 0 || count % 4)
        return NULL;

    olen = count / 4 * 3;
    pos = out = (unsigned char *)malloc(olen);
    if (out == NULL)
        return NULL;

    count = 0;
    for (i = 0; i < len; i++)
    {
        tmp = dtable[src[i]];
        if (tmp == 0x80)
            continue;

        if (src[i] == '=')
            pad++;
        block[count] = tmp;
        count++;
        if (count == 4)
        {
            *pos++ = (block[0] << 2) | (block[1] >> 4);
            *pos++ = (block[1] << 4) | (block[2] >> 2);
            *pos++ = (block[2] << 6) | block[3];
            count = 0;
            if (pad)
            {
                if (pad == 1)
                    pos--;
                else if (pad == 2)
                    pos -= 2;
                else
                {
                    /* Invalid padding */
                    free(out);
                    return NULL;
                }
                break;
            }
        }
    }

    *out_len = pos - out;
    return out;
}

char *read_nth_line(char *string, int line, bool returns)
{
    char *delimeter;
    if (returns)
    {
        delimeter = (char *)"\r\n";
    }
    else
    {
        delimeter = (char *)"\n";
    }

    char *token = strtok(string, delimeter);

    int current_line = 1;
    while (token != NULL)
    {
        if (current_line == line)
        {
            break;
        }
        token = strtok(NULL, delimeter);
        current_line += 1;
    }

    return token;
}

char *read_nth_token(char *string, int token_count)
{
    char *token = strtok(string, " ");

    int current_token_count = 1;
    while (token != NULL)
    {
        if (current_token_count == token_count)
        {
            break;
        }
        token = strtok(NULL, " ");
        current_token_count += 1;
    }

    return token;
}

#define MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
void create_websocket_handshake_key(char *key, char **dest)
{
    char *key_with_magic_string = (char *)calloc(1, sizeof(char) * (61)); // 24 for the key, 36 for the magic string, 1 for the null character
    strncpy(key_with_magic_string, key, 24);
    strcat(key_with_magic_string, MAGIC_STRING);

    SHA1Context ctx;
    unsigned char hash[SHA1HashSize];

    SHA1Reset(&ctx);
    SHA1Input(&ctx, (const uint8_t *)key_with_magic_string, 60);
    SHA1Result(&ctx, hash);

    *dest = (char *)base64_encode(hash, SHA1HashSize, NULL);
    *(*dest + strlen((const char *)*dest) - 1) = '\0';
    free(key_with_magic_string);
}

static void close_socket(int fd)
{
#ifndef _WIN32
    shutdown(fd, SHUT_RDWR);
    close(fd);
#else
    closesocket(fd);
#endif
}

char *handshakeResponse(char *socket_key)
{
    char *handshake_key;
    create_websocket_handshake_key(socket_key, &handshake_key);

    char *headers = (char *)"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";

    char *response = (char *)calloc(1, sizeof(char) * (strlen(handshake_key) + strlen(headers) + 1));
    strncpy(response, headers, strlen(headers));
    strcat(response, handshake_key);

    char *response_with_returns = (char *)calloc(1, sizeof(char) * (strlen(response) + strlen("\r\n\r\n") + 1));
    strncpy(response_with_returns, response, strlen(response));
    strcat(response_with_returns, "\r\n\r\n");

    return response_with_returns;
}

char *handleBuffer(char *buffer)
{
    char *line = strtok(buffer, "\r\n");

    while (line != NULL)
    {
        if (strncmp(line, "Sec-WebSocket-Key:", strlen("Sec-WebSocket-Key:")) == 0)
        {
            break;
        }
        line = strtok(NULL, "\r\n");
    }

    if (!line)
        return 0;

    char *ws_key = strtok(line, " ");
    ws_key = strtok(NULL, " ");

    return handshakeResponse(ws_key);
}

bool read_nth_bit(void *ptr, size_t n)
{
    unsigned char *cptr = (unsigned char *)ptr;
    unsigned char byte = cptr[n / 8];

    return !!(byte & (1 << (n % 8)));
}

#define bit bool
#define byte uint8_t

struct MessageData
{
    byte opcode;
    byte payload_length;
    char *payload;
};

#define OPCODE_CONT 0
#define OPCODE_TXT 1
#define OPCODE_BIN 2
#define OPCODE_CLSE 8
#define OPCODE_PING 0x9
#define OPCODE_PONG 0xA

struct MessageData createMessageData(uint8_t *data)
{
    int masked = 0;
    int payloadLength;
    int byte_count = 0;
    int first_count = 2, i;
    uint8_t maskingKey[4];

    uint8_t b = data[0];
    int fin = ((b & 0x80) != 0);
    int opcode = (uint8_t)(b & 0x0F);

    // Masked + Payload Length
    b = data[1];
    masked = ((b & 0x80) != 0);
    payloadLength = (uint8_t)(0x7F & b);

    if (payloadLength == 0x7F)
    {
        byte_count = 8;
    }
    else if (payloadLength == 0x7E)
    {
        byte_count = 2;
    }

    byte_count += first_count;

    if (byte_count > 2)
    {
        payloadLength = data[byte_count - 1];

        for (i = byte_count - 2; i >= first_count; i--)
        {
            uint8_t bytenum = i - first_count + 1;
            payloadLength |= (data[i] << 8 * bytenum);
        }
    }

    if (masked)
    {
        for (i = 0; i < 4; i++)
        {
            maskingKey[i] = data[byte_count + i];
        }
    }

    uint8_t *payload = (uint8_t *)malloc(sizeof(uint8_t) * payloadLength);
    payload = &data[byte_count + 4];

    if (masked)
    {
        uint64_t len;
        for (len = 0; len < payloadLength; len++)
        {
            payload[len] ^= maskingKey[len % 4];
        }
    }

    payload[payloadLength] = '\0';

    return (struct MessageData){
        (uint8_t)opcode, (uint8_t)payloadLength, (char *)payload};
}

char *createSendData(char *data, int opcode, int *len)
{
    unsigned char frame[10];
    frame[0] = (128 | opcode);
    uint64_t length = (uint64_t)strlen(data);

    int idx_first_rData;

    if (length <= 125)
    {
        frame[1] = length & 0x7F;
        idx_first_rData = 2;
    }
    else if (length >= 126 && length <= 65535)
    {
        frame[1] = 126;
        frame[2] = (length >> 8) & 255;
        frame[3] = length & 255;
        idx_first_rData = 4;
    }
    else
    {
        frame[1] = 127;
        frame[2] = (unsigned char)((length >> 56) & 255);
        frame[3] = (unsigned char)((length >> 48) & 255);
        frame[4] = (unsigned char)((length >> 40) & 255);
        frame[5] = (unsigned char)((length >> 32) & 255);
        frame[6] = (unsigned char)((length >> 24) & 255);
        frame[7] = (unsigned char)((length >> 16) & 255);
        frame[8] = (unsigned char)((length >> 8) & 255);
        frame[9] = (unsigned char)(length & 255);
        idx_first_rData = 10;
    }

    int response_index = 0;
    char *response = (char *)malloc(sizeof(unsigned char) * (idx_first_rData + length + 1));
    for (int i = 0; i < idx_first_rData; i++)
    {
        response[i] = frame[i];
        response_index++;
    }

    /* Add data bytes. */
    for (int i = 0; i < length; i++)
    {
        response[response_index] = data[i];
        response_index++;
    }

    response[response_index] = '\0';
    *len = response_index;
    return response;
}
#include <errno.h>

extern "C" int send_text(int socket, char *text)
{
    // Block so it doesn't send and recieve
    int len = 0;
    char *data = createSendData(text, OPCODE_TXT, &len);
#ifndef _WIN32
    return send(socket, data, len, 0);
#else
    return send(socket, data, len, 0);
#endif
}