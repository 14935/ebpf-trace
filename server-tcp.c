#include <netinet/in.h>  
#include <stdint.h>     
#include <stdio.h>      
#include <sys/socket.h>  
#include "common.h"     

uint8_t buffer[4096];

int main (int argc, char** argv) {
	struct sockaddr_in address =
	 	{ .sin_family = AF_INET
		, .sin_port   = 0x4242
		, .sin_addr   = { 0x00000000 }
		};

	int sockfd = socket (AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		die ("socket() failed");
	}

	if (bind (sockfd, (struct sockaddr*) &address, sizeof (address)) != 0) {
		die ("bind() failed");
	}

	if (listen (sockfd, 10) != 0) {
		die ("listen() failed");
	}
	bpf_load (sockfd, "filter.c", "filter");
	for (;;) {
		int connfd = accept (sockfd, NULL, NULL);

		if (connfd < 0) {
			die ("accept() failed");
		}

		size_t size = recv (connfd, buffer, sizeof(buffer), 0);
		dump (buffer, size);
	}
}
