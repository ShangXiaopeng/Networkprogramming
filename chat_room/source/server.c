#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <utility>
#include <unordered_map>
#include <functional>
#include <time.h>

#include "timer_sorted_list.h"
#include "client_data.h"

#define USER_LIMIT 5
#define BUFFER_SIZE 1024
#define FD_LIMIT 65535
#define MAX_EVENT_NUMBER 1024
#define PROCESS_LIMIT 65536

#define ALRM_INTERVAL 5
#define TICK_TIMES 4

struct pair_hash
{
	template<class T1, class T2>
	std::size_t operator()(const std::pair<T1, T2>& p) const
	{
		std::size_t h1 = std::hash<T1>()(p.first);
		std::size_t h2 = std::hash<T2>()(p.second);
		return h1 ^ h2;
	}
};

static const char* shm_name = "/my_shm";
static timer_sorted_list tsl;

int sig_pipefd[2];
int epollfd;
int listenfd;
int shmfd;

char* share_mem = NULL;
client_data* users = NULL;

std::unordered_map<pid_t,int> hash_pid;

int user_count = 0;
bool stop_child = false;

int setnonblocking(int fd)
{
	int old_option = fcntl(fd, F_GETFL);
	int new_option = old_option | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_option);
	return old_option;
}

void addfd_epollfd(int epollfd, int fd)
{
	epoll_event event;
	event.data.fd = fd;
	event.events = EPOLLIN | EPOLLET;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
	setnonblocking(fd);
}

void sig_handler(int sig) // send signal to parent process
{
	int old_errno = errno;
	int msg = sig;
	send(sig_pipefd[1], (char*) &msg, 1, 0);
	errno = old_errno;
}

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

void callback_func(client_data* user_data)
{
	int pid = user_data->pid;
	kill(pid, SIGTERM);

//	stop_child = true; // another choice
}

void free_resource()
{
	close(sig_pipefd[0]);
	close(sig_pipefd[1]);
	close(listenfd);
	close(epollfd);
	shm_unlink(shm_name);
	delete [] users;
	hash_pid.~unordered_map();
	tsl.~timer_sorted_list();
}

void child_term_handler(int sig)
{
	stop_child = true;
}

int run_child(int idx, client_data* users, char* share_mem)
{
	int connfd = users[idx].connfd;
	int ret;
	char tmp_buffer[NAME_SIZE];
	memset(tmp_buffer, '\0', NAME_SIZE);
	ret = recv(connfd, tmp_buffer, NAME_SIZE - 1, 0);

	if(ret < 0 || ret == 0)
		stop_child = true;

	strcat(tmp_buffer, ": ");
	memset(share_mem + idx * (NAME_SIZE + BUFFER_SIZE), '\0', NAME_SIZE + BUFFER_SIZE);
	strcpy(share_mem + idx * (NAME_SIZE + BUFFER_SIZE), tmp_buffer);
	printf("client %d's name has been set.\n", idx);

	epoll_event events[MAX_EVENT_NUMBER];
	int child_epollfd = epoll_create(5);
	assert(child_epollfd != -1);
	addfd_epollfd(child_epollfd, connfd);
	int pipefd = users[idx].pipefd[1];
	addfd_epollfd(child_epollfd, pipefd);

	addsig(SIGTERM, child_term_handler, false);

	while(!stop_child)
	{
		int number_revents = epoll_wait(child_epollfd, events, MAX_EVENT_NUMBER, -1);
		if((number_revents < 0) && (errno != EINTR))
		{
			printf("epoll failure\n");
			break;
		}

		for(int i = 0; i < number_revents; i++)
		{
			int sockfd = events[i].data.fd;
			if((sockfd == connfd) && (events[i].events & EPOLLIN))
			{
				memset(share_mem + idx * (NAME_SIZE + BUFFER_SIZE) + NAME_SIZE, '\0', BUFFER_SIZE);
				ret = recv(connfd, share_mem + idx * (NAME_SIZE + BUFFER_SIZE) + NAME_SIZE, BUFFER_SIZE - 1, 0);

				if((ret < 0) && (errno != EAGAIN))
					stop_child = true;

				else if(ret == 0)
					stop_child = true;

				else
					send(pipefd, (char*) &idx, sizeof(idx), 0);
			}

			else if((sockfd == pipefd) && (events[i].events & EPOLLIN))
			{
				int client = 0;
				ret = recv(sockfd, (char*) &client, sizeof(client), 0);

				if((ret < 0) && (errno != EAGAIN))
					stop_child = true;

				else if(ret == 0)
					stop_child = true;

				else
				{
					char tmp_buffer[NAME_SIZE + BUFFER_SIZE];
					memset(tmp_buffer, '\0', NAME_SIZE + BUFFER_SIZE);
					strcpy(tmp_buffer, share_mem + client * (NAME_SIZE + BUFFER_SIZE));
					strcat(tmp_buffer, share_mem + client * (NAME_SIZE + BUFFER_SIZE) + NAME_SIZE);
					send(connfd, tmp_buffer, strlen(tmp_buffer), 0);
				}
			}

			else
				continue;
		}
	}

	close(connfd);
	close(pipefd);
	close(child_epollfd);
	return 0;
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

	int ret = 0;
	struct sockaddr_in address;
	bzero(&address, sizeof(address));
	address.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &address.sin_addr);
	address.sin_port = htons(port);

	listenfd = socket(PF_INET, SOCK_STREAM, 0);
	assert(listenfd >= 0);
	
	ret = bind(listenfd, (struct sockaddr*) &address, sizeof(address));
	assert(ret != -1);

	ret = listen(listenfd, 5);
	assert(ret != -1);

	user_count = 0;
	users = new client_data[USER_LIMIT + 1];

	epoll_event events[MAX_EVENT_NUMBER];
	epollfd = epoll_create(5);
	assert(epollfd != -1);
	addfd_epollfd(epollfd, listenfd);

	ret = socketpair(PF_UNIX, SOCK_STREAM, 0, sig_pipefd);
	assert(ret != -1);
	setnonblocking(sig_pipefd[1]);
	addfd_epollfd(epollfd, sig_pipefd[0]);

	addsig(SIGCHLD, sig_handler);
	addsig(SIGTERM, sig_handler);
	addsig(SIGINT, sig_handler);
	addsig(SIGPIPE, SIG_IGN);
	addsig(SIGALRM, sig_handler);
	bool stop_server = false;
	bool terminate = false;
	
	shmfd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
	assert(shmfd != -1);
	ret = ftruncate(shmfd, USER_LIMIT * (NAME_SIZE + BUFFER_SIZE));
	assert(ret != -1);

	share_mem = (char*) mmap(NULL, USER_LIMIT * (NAME_SIZE + BUFFER_SIZE), PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, 0);
	assert(share_mem != MAP_FAILED);
	close(shmfd);

	alarm(ALRM_INTERVAL);

	while(!stop_server)
	{
		int number_revents = epoll_wait(epollfd, events, MAX_EVENT_NUMBER, -1);
		if((number_revents < 0) && (errno != EINTR))
		{
			printf("epoll failure\n");
			break;
		}

		for(int i = 0; i < number_revents; i++)
		{
			int sockfd = events[i].data.fd;
			if(sockfd == listenfd)
			{
				struct sockaddr_in client_address;
				socklen_t client_addrlen = sizeof(client_address);
				int connfd = accept(listenfd, (struct sockaddr*) &client_address, & client_addrlen);
				if(connfd < 0)
				{
					printf("errno is %d\n", errno);
					continue;
				}

				if(user_count >= USER_LIMIT)
				{
					const char* info = "too many users\n";
					printf("%s", info);
					send(connfd, info, strlen(info), 0);
					close(connfd);
					continue;
				}

				users[user_count].address = client_address;
				users[user_count].connfd = connfd;

				ret = socketpair(PF_UNIX, SOCK_STREAM, 0, users[user_count].pipefd);
				assert(ret != -1);
				pid_t pid = fork();
				if(pid < 0)
				{
					close(connfd);
					continue;
				}
				else if(pid == 0) // child process
				{
					close(epollfd);
					close(listenfd);
					close(users[user_count].pipefd[0]);
					close(sig_pipefd[0]);
					close(sig_pipefd[1]);
					run_child(user_count, users, share_mem);
					munmap((void*) share_mem, USER_LIMIT * BUFFER_SIZE);
					exit(0);
				}
				else // parent process
				{
					sl_timer* timer = new sl_timer;
					timer->user_data = &users[user_count];
					timer->callback_func = callback_func;
					time_t curr_time = time(NULL);
					timer->expire_time = curr_time + TICK_TIMES * ALRM_INTERVAL;
					users[user_count].timer = timer;
					tsl.insert_timer(timer);

					close(connfd);
					close(users[user_count].pipefd[1]);
					addfd_epollfd(epollfd, users[user_count].pipefd[0]);
					users[user_count].pid = pid;
					hash_pid.insert(std::make_pair(pid, user_count));
					user_count++;
				}
			}

			else if((sockfd == sig_pipefd[0]) && (events[i].events & EPOLLIN))
			{
				int sig;
				char signals[1024];

				ret = recv(sig_pipefd[0], signals, sizeof(signals), 0);

				if(ret == -1 || ret == 0)
					continue;

				else
				{
					for(int i = 0; i < ret; i++)
					{
						switch(signals[i])
						{
							case SIGCHLD:
							{
								pid_t pid;
								int stat;
								while((pid = waitpid(-1, &stat, WNOHANG)) > 0)
								{
									auto itr = hash_pid.find(pid);
									if(itr == hash_pid.end())
									{
										printf("No this pid: %d \n", pid);
										continue;
									}

									int del_user = (*itr).second;
									hash_pid.erase(itr);

									epoll_ctl(epollfd, EPOLL_CTL_DEL, users[del_user].pipefd[0], 0);
									close(users[del_user].pipefd[0]);

									sl_timer* timer = users[del_user].timer;
									printf("deleting no. %d in all %d clients \n", del_user + 1, user_count);

									if(timer)
									{
										tsl.erase_timer(timer);
									}

									--user_count;

									if(del_user != user_count)
									{
										users[del_user] = users[user_count];
										auto itr2 = hash_pid.find(users[del_user].pid);

										(*itr2).second = del_user;
									}
								}

								if(terminate && user_count == 0)
									stop_server = true;
								break;
							}

							case SIGTERM:
							case SIGINT:
							{
								printf("kill all the child now\n");
								if(user_count == 0)
								{
									stop_server = true;
									break;
								}

								for(int i = 0; i < user_count; i++)
								{
									int pid = users[i].pid;
									kill(pid, SIGTERM);
								}
								terminate = true;
								break;
							}

							case SIGALRM:
							{
								tsl.tick();
								alarm(ALRM_INTERVAL);
								break;
							}

							default:
								break;
						}
					}
				}
			}

			else if(events[i].events & EPOLLIN)
			{
				int child = 0;
				ret = recv(sockfd, (char*) &child, sizeof(child), 0);
				printf("read data from child accross pipe\n");

				if(ret == -1 || ret == 0)
					continue;

				else
				{
					for(int j = 0; j < user_count; j++)
					{
						if(users[j].pipefd[0] != sockfd)
						{
							printf("send data to child accross pipe\n");
							send(users[j].pipefd[0], (char*) &child, sizeof(child), 0);
						}
					}

					sl_timer* timer = users[child].timer;
					time_t curr_time = time(NULL);
					timer->expire_time = curr_time + TICK_TIMES * ALRM_INTERVAL;
					printf("update timer for client %d \n", child);
					tsl.update_timer(timer);
				}
			}
		}
	}

	free_resource();
	return 0;
}





















