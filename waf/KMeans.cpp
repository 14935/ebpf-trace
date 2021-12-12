#include <string>
#include "KMeans.h"
#include "vector"
#include "cmath"
#include "algorithm"
#include "map"

using namespace std;

Point::Point(const std::vector<double>& coords, bool is_malware) {
    this->coords = coords;
    this->is_malware = is_malware;
}

Point::Point(const std::vector<double> & coords) {
    this->coords = coords;
    this->is_malware = -1;
}

double Point::calc_distance(const Point & point) {
    Point delta = *this - point;
    delta = delta * delta;
    return sqrt(delta.sum());
}

Point Point::operator - (const Point& point){
    vector<double> new_coords(this->coords.size(), 0.0);
    for(int i = 0; i < this->coords.size(); i++){
        new_coords[i] = this->coords[i] - point.coords[i];
    }
    return Point(new_coords);
}

Point Point::operator * (const Point& point){
    vector<double> new_coords(this->coords.size(), 0.0);
    for(int i = 0; i < this->coords.size(); i++){
        new_coords[i] = this->coords[i] * point.coords[i];
    }
    return Point(new_coords);
}

double Point::sum(){
    double res = 0;
    for(double coord : this->coords){
        res += coord;
    }
    return res;
}

int Point::getIsMalware() const {
    return this->is_malware;
}

KnnClassifier::KnnClassifier(int k) {
    this->k = k;
}

void KnnClassifier::fit(const std::vector<Point> & new_points) {
    this->points = new_points;
}

int KnnClassifier::predict(const Point& point){
    vector<pair<double, int>> result;
    for(auto & i : this->points){
        double distance = i.calc_distance(point);
        result.emplace_back(distance, i.getIsMalware());
    }
    sort(result.begin(),
         result.end(), [](
                 const pair<double, int>& a,
                 const pair<double, int>& b)->bool{return fabs(a.first - b.first) <= 1e-5;
    });

    map<int, int> count = {{1, 0}, {0, 0}, {-1, 0}};
    for(pair<double, int> res_i: result){
        count[res_i.second] += 1;
    }

    return max(count.begin(), count.end(), [](
            _Rb_tree_iterator<pair<const int, int>> a,
            _Rb_tree_iterator<pair<const int, int>> b)->bool{return a->second < b->second;})->first;
}