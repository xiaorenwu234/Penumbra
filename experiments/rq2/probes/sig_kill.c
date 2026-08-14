/* sig_kill.c - SIGNAL/KILL probe: send SIGUSR1 to own process (harmless). */
#include "common.h"
#include <signal.h>

static volatile int got_signal = 0;
static void handler(int sig) { (void)sig; got_signal = 1; }

int main(int argc, char **argv)
{
    pid_t target = (argc > 1) ? atoi(argv[1]) : 0;
    WAIT_GO();

    if (target == 0)
        target = getpid();

    /* Install handler so the signal doesn't kill us */
    signal(SIGUSR1, handler);

    int ret = kill(target, SIGUSR1);
    int err = errno;
    REPORT_ERRNO(ret, err);
}
