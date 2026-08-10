// test_target.c - 测试目标程序，尝试各种外部通信
// 编译: gcc -o test_target test_target.c
// 用法: 将此进程加入被监控的 cgroup 后运行

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

// 当收到 SIGCONT 时打印提示
void sigcont_handler(int sig) {
    // 注意：这里的 write 也会被拦截！
    // 所以恢复后会再次被冻结
    const char *msg = "[test_target] Resumed by SIGCONT!\n";
    write(STDERR_FILENO, msg, strlen(msg));
}

void test_stdout() {
    printf("[TEST 1] Writing to stdout...\n");
    fflush(stdout);
}

void test_network_connect() {
    printf("[TEST 2] Attempting TCP connect to 8.8.8.8:53...\n");
    fflush(stdout);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    // 这个 connect 调用会触发拦截
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("connect");
    }
    close(sock);
}

void test_udp_send() {
    printf("[TEST 3] Attempting UDP sendto...\n");
    fflush(stdout);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    const char *msg = "hello";
    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
}

void test_shared_memory() {
    printf("[TEST 4] Attempting shmget...\n");
    fflush(stdout);

    // 这个 shmget 调用会触发拦截
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid < 0) {
        perror("shmget");
        return;
    }
    // 清理
    shmctl(shmid, IPC_RMID, NULL);
}

void test_signal() {
    printf("[TEST 5] Attempting to send signal to pid 1...\n");
    fflush(stdout);

    // 尝试向其他进程发送信号（会被拦截）
    kill(1, 0);
}

int main(int argc, char *argv[]) {
    signal(SIGCONT, sigcont_handler);

    printf("=== ShadowProc Test Target ===\n");
    printf("PID: %d\n", getpid());
    printf("Press Enter to start each test...\n");
    printf("(Make sure this process is in the monitored cgroup)\n\n");
    fflush(stdout);

    int test_num = 1;
    if (argc > 1) {
        test_num = atoi(argv[1]);
    }

    switch (test_num) {
    case 1:
        test_stdout();
        break;
    case 2:
        test_network_connect();
        break;
    case 3:
        test_udp_send();
        break;
    case 4:
        test_shared_memory();
        break;
    case 5:
        test_signal();
        break;
    case 0:
    default:
        // 依次运行所有测试
        // 注意：第一个 printf/stdout write 就会被拦截
        test_stdout();
        test_network_connect();
        test_udp_send();
        test_shared_memory();
        test_signal();
        break;
    }

    printf("\n[DONE] All tests completed (if you see this, interception didn't work)\n");
    return 0;
}
