#include <stdio.h>
#include <stdlib.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <execinfo.h>

#define MAX_FRAMES 20
#define MAX_STRING_LEN 1024
#define FRONT_COLOR_RED "\033[31m"
#define FRONT_COLOR_NONE "\033[0m"
#define DELIMITER "======================================="

// 获取原始调用栈信息
int get_call_stack(char ***symbols) {
    void *stack[MAX_FRAMES];
    int frames = backtrace(stack, MAX_FRAMES);

    *symbols = backtrace_symbols(stack, frames);
    if (*symbols == NULL) {
        perror("backtrace_symbols");
        return -1;
    }

    return frames;
}

void getBaseAddr(char *binaryName, char *baseAddr) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char buffer[MAX_STRING_LEN];
    const char *dash_pos;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if ((strstr(buffer, binaryName) != NULL) && (strchr(buffer, '-') != NULL) && (strstr(buffer, "r-xp") != NULL)) {
            dash_pos = strchr(buffer, '-');
            size_t length = dash_pos - buffer;
            strncpy(baseAddr, buffer, length);
            baseAddr[length] = '\0';
            break;
        }
    }
    fclose(fp);
}


// 计算两个十六进制字符串的相减结果
void hex_subtract(const char* hex1, const char* hex2, char* result_str) {
    unsigned long long num1 = strtoull(hex1, NULL, 16);
    unsigned long long num2 = strtoull(hex2, NULL, 16);
    unsigned long long result = num1 - num2;

    sprintf(result_str, "%llx", result); // 小写十六进制
}

void executeCommand(const char *command, char *output, size_t outputLength) {
    FILE *fp;

    fp = popen(command, "r");
    if (fp == NULL) {
        snprintf(output, outputLength, "Error: Failed to run command");
        return;
    }
    size_t bytesRead = fread(output, 1, outputLength - 1, fp);
    output[bytesRead] = '\0';

    pclose(fp);
}

void getAddresses(const char *input, char *traceAddr) {
    const char *start = NULL;
    const char *end = NULL;

    start = strchr(input, '[');
    end = strchr(start, ']');
    if (start != NULL && end != NULL) {
        size_t length = end - start - 1;
        strncpy(traceAddr, start + 1, length);
        traceAddr[length] = '\0';
    }
}

void getFuncName(const char *input, char *funcName){
    const char *start = NULL;
    const char *pos = NULL;
    const char *end = NULL;

    start = strchr(input, '(');
    pos = strchr(start, '+');
    end = strchr(start, ')');
    if (start != NULL && pos != NULL && end != NULL) {
        size_t length = pos - start - 1;
        strncpy(funcName, start + 1, length);
        funcName[length] = '\0';
    }
}

void getBinaryPath(const char *input, char *binaryPath){
    const char *pos = NULL;
    pos = strchr(input, '(');

    if (pos != NULL) {
        int length = pos - input;
        strncpy(binaryPath, input, length);
        binaryPath[length] = '\0';
    }
}

void get_call_stack_with_line()
{
    int i;
    char realAddr[MAX_STRING_LEN];
    char traceAddr[MAX_STRING_LEN];
    char funcName[MAX_STRING_LEN];
    char baseAddr[MAX_STRING_LEN];
    char binaryPath[MAX_STRING_LEN];
    char cmdStr[MAX_STRING_LEN];
    char output[MAX_STRING_LEN];
    char result[MAX_STRING_LEN];
    char **messages;
    int msgLen;

    result[0] = '\0';
    strcat(result, "" FRONT_COLOR_RED "" DELIMITER "Call Stack" DELIMITER "" FRONT_COLOR_NONE "\n");
    msgLen = get_call_stack(&messages);
    for (i = 2; i < msgLen; i++) {
        getAddresses(messages[i], traceAddr);
        getFuncName(messages[i], funcName);
        getBinaryPath(messages[i], binaryPath);
        getBaseAddr(binaryPath, baseAddr);

        if (strstr(binaryPath, ".so") != NULL) {
            hex_subtract(traceAddr, baseAddr, realAddr);
            hex_subtract(realAddr, "0x1", realAddr);
            sprintf(cmdStr, "addr2line -e %s %s", binaryPath, realAddr);
        } else {
            hex_subtract(traceAddr, "0x1", realAddr);
            sprintf(cmdStr, "addr2line -e  %s -i %s", binaryPath, realAddr);
        }
        executeCommand(cmdStr, output, 1024);
        sprintf(result + strlen(result), "#%d %s %s", i - 2, funcName, output);
    }
    sprintf(result + strlen(result), "" FRONT_COLOR_RED "Process %d quit" DELIMITER "" FRONT_COLOR_NONE "\n", getpid());
    printf("%s", result);
}
