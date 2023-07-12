#ifndef CLIENT_DATA_H_
#define CLIENT_DATA_H_

#define NAME_SIZE 32

class sl_timer;

struct client_data
{
	sockaddr_in address;
	int connfd;
	pid_t pid;
	int pipefd[2];
	sl_timer* timer;
	char name[NAME_SIZE];
};

#endif

























