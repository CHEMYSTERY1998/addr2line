#include "addr2line.h"

void functionE() {
    get_call_stack_with_line();
}

void functionD() {
    functionE();
}

void functionC() {
    functionD();
}

void functionB() {
    functionC();
}

void functionA() {
    functionB();
}

int main(int argc, char *argv[]) {
    functionA();
    return 0;
}
