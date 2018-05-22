#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <stdio.h>

using namespace std;

void test()
{
	unsigned int i = 231324;
	stringstream ss1;
	ss1 << "haha" << endl;
	std::cout << hex << ss1.str();

}

void test2()
{
	int size = 6;
	char *op = (char *)malloc(size);
	unsigned int i = 0x123456781122;
	memcpy(op, &i, size);
	printf("%x\n", *op);
}
int main()
{
	int a = 5;
	int b = 3;
	int tmp;
	tmp = a;
	a = b;
	b = tmp;
	test2();
	printf("a = %d, b = %d", a, b);
	return 0;
}

