#pragma once

#include <stddef.h> 
#include <stdint.h> 

void bpf_load (int sockfd, char* file, char* function);
void die (const char* message);
void dump (uint8_t* data, size_t size);
