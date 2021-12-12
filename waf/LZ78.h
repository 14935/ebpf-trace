#include "vector"
#include "string"
#ifndef WAF_LZ78_H
#define WAF_LZ78_H

struct Node{
    int pos;
    char next;
};

std::vector<Node> encodeLZ78(const std::string&);
std::string decodeLZ78(const std::vector<Node>&);

#endif