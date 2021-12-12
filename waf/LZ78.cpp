#include "LZ78.h"
#include "vector"
#include "map"

using namespace std;

vector<Node> encodeLZ78(const string& s){
    string buffer;
    map<string, int> dict;
    vector<Node> ans = {};
    for(char i : s){
        if (dict.find(buffer + i) != dict.end()){
            buffer += i;
        } else {
            ans.push_back({dict[buffer], i});
            dict[buffer + i] = dict.size();
            buffer = "";
        }
    }
    if (!buffer.empty()){
        char last_ch = *(buffer.end()-1);
        buffer.pop_back();
        ans.push_back({dict[buffer], last_ch});
    }
    return ans;
}

string decodeLZ78(const vector<Node>& encoded){
    vector<string> dict = {""};
    string ans;
    for(Node node: encoded){
        string word = dict[node.pos] + node.next;
        ans += word;
        dict.push_back(word);
    }
    return ans;
}