#include <winsock2.h>
#include <stdio.h>

void http_response(SOCKET con, const char* request)
{
    char * uri = strtok(0, " ");
    char file[64];
    sprintf(file, ".%s", uri);

    FILE* fp = fopen(file, "rb");
    if(fp == 0)
    {
        char response[] = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
        send(con, response, strlen(response), 0);
    }
    else
    {
        int file_size;
        char* content;
        char response[1024];
        fseek(fp, 0, SEEK_END);
        file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        content = (char*)malloc(file_size+1);
        fread(content, file_size, 1, fp);
        content[file_size] = '\0';

        sprintf(response, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s",
                file_size, content);
        send(con, response, strlen(response), 0);
        free(content);
    }
}

int main()
{
    WSADATA wd;
    int ret;
    SOCKET s;

    ret = WSAStartup(MAKEWORD(2,0), &wd);
    if(ret < 0)
    {
        fprintf(stderr, "winsock startup failed\n");
        exit(-1);
    }
    s = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    ret = bind(s, (struct sockaddr*)&addr, sizeof(addr));

    if(ret < 0)
    {
        fprintf(stderr, "bind failed\n");
        closesocket(s);
        exit(-1);
    }
    ret = listen(s, 1024);
    if(ret < 0)
    {
        fprintf(stderr, "listen failed\n");
        closesocket(s);
        exit(-1);
    }

    SOCKET con = accept(s, 0, 0);
    char request[1024] = {'\0'};
    ret = recv(con, request, sizeof(request), 0);
    printf(request);
    http_response(con,request);
    closesocket(con);
    closesocket(s);
    WSACleanup();

    return 0;
}
