#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define SERVER_PORT     8081
#define RX_BUFFER_SIZE  4096
#define CLIENT_KEY_SIZE 256

int send_ws_message(int socket, const char* data, int data_len)
{
    unsigned char ws_frame[512];
    //const char *msg = "{\r\n\"state\":\"login\"\r\n}";
    //size_t msg_len = strlen(msg);

    ws_frame[0] = 0x81;  // FIN=1, text frame
    ws_frame[1] = data_len; // uzunluk (125'ten küçük olduğu için tek byte yeterli)
    memcpy(&ws_frame[2], data, data_len);

    return send(socket, ws_frame, data_len + 2, 0);
}

void* clientThread(void *arg)
{
    int ret;
    int socketID = *((int *)arg);
    char* client_key = malloc(CLIENT_KEY_SIZE);
    char* buffer = malloc(RX_BUFFER_SIZE);
    char* key_addr;
    int ret_size;

    if(NULL == buffer)
    {
        printf(" - Memory Allocation ERROR for Socket %d \r\n", socketID);
        return NULL;
    }

    printf("Running Task %d\r\n", socketID);

    while(1)
    {
        /* sleep thread */
        usleep(1000);
        

        // Clear the memory
        memset(buffer, 0, RX_BUFFER_SIZE);

        // Read the available data
        ret_size = read(socketID, buffer, RX_BUFFER_SIZE);
        if(ret_size > 0)
        {
            // "Sec-WebSocket-Key" bul
            key_addr = strstr(buffer, "Sec-WebSocket-Key: ");
            if(NULL != key_addr)
            {
                memset(client_key, 0, CLIENT_KEY_SIZE);

                key_addr += strlen("Sec-WebSocket-Key: ");
                sscanf(key_addr, "%s", client_key);

                printf("Client %d - Key: %s \r\n", socketID, client_key);

                // GUID ile birleştir - Bu GUID RFC6455 ve RFC4122 de tanimlanmiştir
                char to_hash[256];
                snprintf(to_hash, sizeof(to_hash), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);

                // SHA1 hesapla
                unsigned char sha1_result[SHA_DIGEST_LENGTH];
                SHA1((unsigned char*)to_hash, strlen(to_hash), sha1_result);
                
                unsigned char encoded_data[CLIENT_KEY_SIZE];
                memset(encoded_data, 0, CLIENT_KEY_SIZE);

                // Base64 encode
                EVP_EncodeBlock((unsigned char*)&encoded_data, (const unsigned char*)&sha1_result, SHA_DIGEST_LENGTH);

                printf("Base64 Encoded Data: %s \r\n", encoded_data);

                // Handshake cevabı gönder
                char response[2*CLIENT_KEY_SIZE];
                memset(response, 0, 2*CLIENT_KEY_SIZE);

                snprintf(response, sizeof(response),
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: %s\r\n\r\n",
                        encoded_data);

                ret = send(socketID, response, strlen(response), 0);
                if(ret > 0)
                {
                    printf("Total %d Bytes Handshake data sended...\r\n", ret);
                }
                
                const char *msg = "{\r\n\"state\":\"login\"\r\n}";
                int msg_len = strlen(msg);
                ret = send_ws_message(socketID, msg, msg_len);
                if(ret > 0)
                {
                    printf("Total %d Bytes WS data sended...\r\n", ret);
                }

            }
            else 
            {
                printf("Other Data: %s\r\n", buffer);
            }
        }
        else if (ret_size == 0) 
        {
            printf(" Client %d Dead !!!\r\n", socketID);
            close(socketID);
            return NULL;
        }

    }
}


int 
server_start(void)
{
    int ret;
    struct timeval tv;
    int serverSocket;
    int newSocket;
    int opt = 1;
    int i=0;
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;
    pthread_t threadIDList[10];

    /* create main socket */ 
    serverSocket = socket(PF_INET, SOCK_STREAM, 0);
    ret = setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if(ret < 0)
    {
        printf(" - Socket option setting ERROR !!\r\n");
        return -1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY; // inet_addr("127.0.0.1");

    memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));

    ret = bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if(ret < 0)
    {
        printf(" - Server Socket Binding ERROR !!\r\n");
        return -2;
    }

    /* listen the connection port */
    if(0 == listen(serverSocket,100))
    {
        printf(" > Server Started on Port %d\r\n", SERVER_PORT);

        while(1)
        {
            addr_size = sizeof(serverStorage);
            newSocket = accept(serverSocket, (struct sockaddr *) &serverStorage, &addr_size);

            tv.tv_sec = 0;
            tv.tv_usec = 200;
            setsockopt(newSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

            ret = pthread_create(&threadIDList[i++], NULL, clientThread, &newSocket); 
            if(0 == ret)
            {
                printf("Client Connected (Thread Created)...\r\n");
            }
            else 
            {
                printf("Client Thread Create ERROR !!!\r\n");
            }
        }
    }
    else
    {
        printf(" - Server Start ERROR !!!\r\n");
    }
    

    return ret;
}

int 
main(void)
{
    server_start();
    return 0;
}

/*
int main() 
{
    int server_fd, client_fd;
    struct sockaddr_in address;
    char buffer[4096] = {0};
    int opt = 1;
    int ret;
    int addrlen = sizeof(address);

    char encoded_data[512];

    // Socket oluştur
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT);

    ret = bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    if(ret < 0)
    {
        printf("Bind Error %d\r\n", ret);
    }

    memset(encoded_data, 0, sizeof(encoded_data));

    ret = listen(server_fd, 3);
    if(ret < 0)
    {
        printf("Listen Error %d\r\n", ret);
    }
    
    printf("WebSocket Server Listen on Port %d ...\n", SERVER_PORT);

    client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);

    read(client_fd, buffer, 4096);
    printf("Handshake Request:\n%s\n", buffer);

    // "Sec-WebSocket-Key" bul
    char *key = strstr(buffer, "Sec-WebSocket-Key: ");
    key += strlen("Sec-WebSocket-Key: ");
    char client_key[256];
    sscanf(key, "%s", client_key);

    // GUID ile birleştir - Bu GUID RFC6455 ve RFC4122 de tanimlanmiştir
    char to_hash[256];
    snprintf(to_hash, sizeof(to_hash), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);

    // SHA1 hesapla
    unsigned char sha1_result[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)to_hash, strlen(to_hash), sha1_result);

    // Base64 encode
    EVP_EncodeBlock((unsigned char*)&encoded_data, (const unsigned char*)&sha1_result, SHA_DIGEST_LENGTH);

    printf("Base64 Encoded Data: %s \r\n", encoded_data);

    // Handshake cevabı gönder
    char response[512];
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n",
             encoded_data);

    ret = send(client_fd, response, strlen(response), 0);
    if(ret > 0)
    {
        printf("Total %d Bytes Handshake data send...\r\n", ret);
    }

    printf("Handshake Completed ! - Test Data Sending...\n");

    // ⚠️ Buradan sonra gönderilecek olan verileri WebSocket frame formatına göre düzenlemek gerekir.
    // Browser tarafı gelen paketi direk olarak çözecektir.

    unsigned char ws_frame[200];
    const char *msg = "{\r\n\"state\":\"login\"\r\n}";
    size_t msg_len = strlen(msg);

    ws_frame[0] = 0x81;  // FIN=1, text frame
    ws_frame[1] = msg_len; // uzunluk (125'ten küçük olduğu için tek byte yeterli)
    memcpy(&ws_frame[2], msg, msg_len);

    send(client_fd, ws_frame, msg_len + 2, 0);

    close(client_fd);
    close(server_fd);
    return 0;
}

*/