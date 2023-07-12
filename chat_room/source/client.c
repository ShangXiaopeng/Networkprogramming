#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <fcntl.h>

#include <signal.h>
#include <libgen.h>

#define BUFFER_SIZE 1024
#define NAME_SIZE 32


void addsig(int sig, void(*handler)(int), bool restart = true)
{
	struct sigaction sa;
	memset(&sa, '\0', sizeof(sa));
	sa.sa_handler = handler;
	if(restart)
		sa.sa_flags |= SA_RESTART;

	sigfillset(&sa.sa_mask);
	assert(sigaction(sig, &sa, NULL) != -1);
}

int main(int argc, char* argv[])
{
	if(argc < 3)
	{
		printf("usage: %s ip_address port_number\n", basename(argv[0]));
		return 1;
	}

	const char* ip = argv[1];
	int port = atoi(argv[2]);

	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &server_addr.sin_addr);
	server_addr.sin_port = htons(port);
	int sockfd = socket(PF_INET, SOCK_STREAM, 0);
	assert(sockfd >= 0);
	if(connect(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0)
	{
		printf("connection failed\n");
		close(sockfd);
		return 1;
	}

	printf("Your nickname (Press Enter for Anonymous)?\n");
	char name[NAME_SIZE];
	memset(name, '\0', NAME_SIZE);

	fgets(name, NAME_SIZE, stdin);

	if(name[0] == '\r' || name[0] == '\n' || name[0] == '\0')
	{
		strcpy(name, "Anonymous");
		name[strlen(name)] = '\0'; // strlen(name) does not include \n
	}
	else
		name[strlen(name) - 1] = '\0'; // strlen(name) includes \n
	printf("Your name: %s\n", name);

	int ret = send(sockfd, name, strlen(name), 0);

	if(ret < 0 || ret == 0)
	{
		printf("send name fail!\n");
		return 1;
	}



	struct pollfd fds[2];
	fds[0].fd = 0;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	fds[1].fd = sockfd;
	fds[1].events = POLLIN | POLLRDHUP;
	fds[1].revents = 0;

	char read_buf[BUFFER_SIZE];
	int pipefd[2];
	ret = pipe(pipefd);
	assert(ret != -1);
	
	while(1)
	{
		ret = poll(fds, sizeof(fds), -1);
		if(ret < 0)
		{
			printf("poll failure\n");
			break;
		}

		if(fds[1].revents & POLLRDHUP)
		{
			printf("server close the connection\n");
			break;
		}

		else if(fds[1].revents & POLLIN)
		{
			memset(read_buf, '\0', BUFFER_SIZE);
			recv(fds[1].fd, read_buf, BUFFER_SIZE - 1, 0);
			printf("%s\n", read_buf);
		}

		if(fds[0].revents & POLLIN)
		{
			ret = splice(0, NULL, pipefd[1], NULL, 32768, SPLICE_F_MORE | SPLICE_F_MOVE);
			ret = splice(pipefd[0], NULL, sockfd, NULL, 32768, SPLICE_F_MORE | SPLICE_F_MOVE);
		}
	}

	close(sockfd);
	return 0;
}
