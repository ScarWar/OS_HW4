#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#define report_error(str) printf("LINE: %d, Error - %s %s\n", __LINE__, (str), strerror(errno))
#define BUFFER_SIZE 2048
#define NUM_OF_PRINTABLE_CHAR 95
#define PORT_NUM 2233
#define min(s, t) ((s) < (t) ? (s) : (t))

typedef struct statistics_data_t {
    long long char_statistics[NUM_OF_PRINTABLE_CHAR] = {0};
} StatisticsData;

static StatisticsData global_sd;
static long long global_n_bytes_read = 0;
pthread_mutex_t lock;


void my_signal_handler(int signum, siginfo_t *info, void *ptr) {
    /* Calculate pipe name */
    pid_t child_pid = info->si_pid;

    /* Stop listening the port. Close the socket. */
    /* Wait for all running threads to finish. */
    /* Print the global bytes counter. */
    printf("The number of bytes read by server is %lld\n", global_n_bytes_read);
    /* Print the global statistics. */

    /* Exit process. */


}

int is_printable(char c) {
    return 32 <= c && c <= 126;
}

int count_printable(char *buf, int length, StatisticsData *sd) {
    int i;
    char c;
    if (buf == NULL || sd == NULL) {
        report_error("Null pointer argument");
        return -1;
    } else if (length < 0) {
        report_error("Invalid argument");
        return -1;
    }

    for (i = 0; i < length; ++i) {
        c = buf[i];
        if (is_printable(c))
            sd->char_statistics[c - 32]++;
    }
    return 0;

}


void *start_client_thread(void *arg) {
    long long n_bytes_read = 0, n_bytes_recv = 0,
            LEN, total_read, n_printable_bytes,
            total_sent, n_bytes_sent, n_bytes_to_read;
    int i;
    char *buf = NULL, print_buf = NULL;
    /* Create a statistics local data structure. */
    StatisticsData *sd = (StatisticsData *) malloc(sizeof(StatisticsData));
    if (!sd) {
        report_error("Memory allocation failed");
        pthread_exit(NULL);
    }
    int sockfd = *((int *) arg);

    /*
    Read the content from the socket. For every byte:
        - Increment the number of bytes read.
        - Decide whether it is printable or not.
        - If it is, then update the local statistics.
    */
    while (total_read < sizeof(int)) {
        n_bytes_recv = recv(sockfd, &LEN + total_sent, sizeof(int) - total_sent, 0);
        if (n_bytes_recv < 0) {
            report_error("Failed to read from client");
            free(sd);
            pthread_exit(NULL);
        }
        total_read += n_bytes_recv;
    }

    n_bytes_read = 0;
    buf = (char *) malloc(BUFFER_SIZE);
    if (!buf) {
        report_error("Memory allocation failed");
        free(sd);
        free(buf);
        pthread_exit(NULL);
    }
    while (n_bytes_read < LEN) {
        n_bytes_to_read = min(LEN - n_bytes_read, BUFFER_SIZE);
        n_bytes_recv = recv(sockfd, buf, (size_t) (LEN - n_bytes_read), 0);
        if (n_bytes_recv < 0) {
            report_error("Failed to read from socket");
            free(sd);
            free(buf);
            pthread_exit(NULL);
        }
        if (!count_printable(buf, (int) n_bytes_recv, sd)) {
            // TODO error - handle thread error
        }
        n_bytes_read += n_bytes_recv;
    }

    /* Send the number of the printable bytes back to the client. */
    n_printable_bytes = 0;
    for (i = 0; i < NUM_OF_PRINTABLE_CHAR; ++i)
        n_printable_bytes += sd->char_statistics[i];

    total_sent = 0;
    while (total_sent < sizeof(int)) {
        n_bytes_sent = send(sockfd, &n_printable_bytes + total_sent, sizeof(long long) - total_sent, 0);
        if (n_bytes_sent < 0) {
            report_error("Failed to send to server");
            if (close(sockfd) < 0)
                report_error("Failed to close socket");
            pthread_exit(NULL);
        }
        total_sent += n_bytes_sent;
    }

    /* Close the connection. */
    close(sockfd);

    /* Acquire (lock) mutex. */
    if (!pthread_mutex_lock(&lock)) {
        // TODO
    }

    /* Add local statistics to GLOB STATS. */
    for (i = 0; i < NUM_OF_PRINTABLE_CHAR; ++i)
        global_sd->char_statistics[i] += sd->char_statistics[i]

    /* Add the number of bytes read by this thread to the global counter. */
    global_n_bytes_read += n_bytes_read;

    /* Release (unlock) mutex. */
    if (!pthread_mutex_unlock(&lock)) {
        // TODO 
        break;
    }
    /* Exit thread. */
    pthread_exit(NULL);
}


int main(int argc, char const *argv[]) {


    /* Structure to pass to the registration syscall */
    struct sigaction new_action;
    memset(&new_action, 0, sizeof(new_action));
    /* Assign pointer to our handler function */
    new_action.sa_handler = (__sighandler_t) my_signal_handler;
    /* Setup the flags */
    new_action.sa_flags = SIGINT;

    if (0 != sigaction(SIGUSR1, &new_action, NULL)) {
        report_error("Signal handle registration failed");
        return -1;
    }

    return 0;
}