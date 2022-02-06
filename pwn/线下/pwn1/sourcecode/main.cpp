#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#define i0gan_asm_1 \
    __asm__ __volatile__( \
    "leaq    (%rip), %r8\n\t" \
    "pushq %r8\n\t" \
    "addq $0xd, (%rsp)\n\t" \
    "ret\n\t" \
    "jmp 0xdeed\n\t");

void func();
void menu();
void init();
void show();
void del();
void add();
char *plist[12];

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    std::cout << "Welcome to 2021 axb awd" << std::endl;
}

void menu() {
    std::cout << ">>";
}

void func() {
    int a = 0;
    int times = 0;
    while(times < 50) {
        menu();
        std::cin >> a; 
        switch(a) {
            case 1: add(); break;
            case 2: del(); break;
            case 3: show(); break;
            default: 
                exit(0);
        }
        ++times;
    }
}

void add() {
    size_t size;
    int idx;
    std::cout << "???" << std::endl;
    std::cin >> size;
    for(idx = 0; idx <= 12; ++idx) {
        if(plist[idx] == nullptr) {
            break;
        }
        if(idx == 12) {
            std::cout << "!!!" << std::endl;
            return;
        }
    }

    if(size <= 0 || size >= 0x100) {
        std::cout << "!#@$%" << std::endl;
        return;
    }

    plist[idx] = new char[size];
    std::cout << ":>";
    size_t i = 0;
    for(i = 0; i < size; ++i) {
        read(0, plist[idx] + i, 1);
        if(*(plist[idx] + i) == '\n')
            break;
    }
    //i0gan_asm_1
    if(plist[idx][0] == 0)
        *(plist[idx] + i) = '\x00';
}

void del() {
    int idx;
    std::cout << "???" << std::endl;
    std::cin >> idx;
    if(idx < 0 || idx >= 12) return;

    if(plist[idx] == nullptr) {
        std::cout << "!!!" << std::endl;
        return ;
    }

    delete[] plist[idx];
    plist[idx] = nullptr;
}

void show() {
    int idx;    
    std::cout << "???" << std::endl;
    std::cin >> idx;
    if(idx < 0 || idx >= 12) return ;
    if(plist[idx] == nullptr) {
        std::cout << "!!!" << std::endl;
        return ;
    }
    std::cout << "$->" << plist[idx] << std::endl;
}

int main(int, char**) {
    init();
    func();
    return 0;
}
