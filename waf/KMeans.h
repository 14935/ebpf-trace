#include <map>
#include "vector"

#ifndef WAF_KMEANS_H
#define WAF_KMEANS_H

class Point{
private:
    std::vector<double> coords;
    int is_malware; // 1 - is malware, 0 - is not malware, -1 - is not defined (need be classifier)
public:
    Point(const std::vector<double>&, bool);
    explicit Point(const std::vector<double>&);

    Point operator - (const Point&);
    Point operator * (const Point&);
    double sum();
    double calc_distance(const Point&);

    [[nodiscard]] int getIsMalware() const;
};

class KnnClassifier{
private:
    std::vector<Point> points;
    int k; // count of classes
public:
    explicit KnnClassifier(int);

    void fit(const std::vector<Point>&);
    int predict(const Point& point);
};
#endif
