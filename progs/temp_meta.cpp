#include <iostream>

template<long N>
class Fact
{   public:
        enum { result = N * Fact<N - 1>::result };
};
template<>
class Fact<0>
{   public:
        enum { result = 1 };
};

int main()
{   std::cout << Fact<100>::result;
    return 0;
}

