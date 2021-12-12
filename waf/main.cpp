#include <iostream>
#include <vector>
#include <map>
#include "LZ78.h"
#include "KMeans.h"

using namespace std;

int main() {
    vector<Point> points = {
            Point(), Point(1.0,0.5), Point(-1.5,0.5),
            Point(1,1), Point(2.0,0.5), Point(-1.5,-0.5),
            Point(2,2), Point(1.0,1.5), Point(-1.75,0.5),
            Point(-1,-1), Point(1.5,0.5), Point(1.5,0.75),
            Point(-2,-2), Point(-1,0.5), Point(-1.25,1.5),
            Point(1.5,1.5), Point(-2.0,-0.5), Point(-0.5,0.25),
            Point(-1.5,-1.5), Point(-1.5,-0.5), Point(1.25,-0.75),
            Point(0.5, 0.5), Point(1.25,0.75), Point(0.25,-1.75),
            Point(-0.5,-0.5), Point(-0.25,0.5), Point(-1.75,0.25),
            Point(0.25,0.25), Point(0.75,-2), Point(-1.75,0.75),
            Point(-0.25,-0.25), Point(1.0,-2.5), Point(-1.25,0.25),
    };
    KMeansClustering(&points, 5);
    return 0;
}
