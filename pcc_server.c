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
#define NUM_THREADS 10
#define min(s, t) ((s) < (t) ? (s) : (t))

typedef struct statistics_data_t {
    long long char_statistics[NUM_OF_PRINTABLE_CHAR];
} StatisticsData;

static StatisticsData *global_sd;
static long long global_n_bytes_read = 0;
static int listenfd;
pthread_t threads[NUM_THREADS];
pthread_mutex_t lock;
char exit_flag;


void my_signal_handler(int signum, siginfo_t *info, void *ptr) {
    int i;
    /* Stop listening the port. Close the socket. */
    close(listenfd);

    /* Wait for all running threads to finish. */
    for (i = 0; i < NUM_THREADS; ++i)
        pthread_join(threads[i], NULL);

    /* Print the global bytes counter. */
    printf("The number of bytes read by server is %lld\n", global_n_bytes_read);

    /* Print the global statistics. */
    printf("we saw ");
    for (i = 0; i < NUM_OF_PRINTABLE_CHAR; ++i) {
        printf("%lld '%c'", global_sd->char_statistics[i], i + 32);
        if (i == NUM_OF_PRINTABLE_CHAR) {
            break;
        }
        printf(", ");
    }

    /* Exit process. */
    exit_flag = 1;
    pthread_exit(NULL);

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
            total_read = 0, n_printable_bytes,
            total_sent = 0, n_bytes_sent, n_bytes_to_read;
    int i, LEN = 0;
    char *buf = NULL;
    /* Create a statistics local data structure. */
    StatisticsData *sd = (StatisticsData *) malloc(sizeof(StatisticsData));
    if (!sd) {
        report_error("Memory allocation failed");
        exit(-1);
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
            exit(-1);
        }
        total_read += n_bytes_recv;
    }

    n_bytes_read = 0;
    buf = (char *) malloc(BUFFER_SIZE);
    if (!buf) {
        report_error("Memory allocation failed");
        free(sd);
        free(buf);
        exit(-1);
    }
    while (n_bytes_read < LEN) {
        n_bytes_to_read = min(LEN - n_bytes_read, BUFFER_SIZE);
        n_bytes_recv = recv(sockfd, buf, (size_t) (n_bytes_to_read), 0);
        if (n_bytes_recv < 0) {
            report_error("Failed to read from socket");
            free(sd);
            free(buf);
            exit(-1);
        }
        if (!count_printable(buf, (int) n_bytes_recv, sd)) {
            exit(-1);
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
            exit(-1);
        }
        total_sent += n_bytes_sent;
    }

    /* Close the connection. */
    close(sockfd);

    /* Acquire (lock) mutex. */
    if (!pthread_mutex_lock(&lock)) {
        exit(-1);
    }

    /* Add local statistics to GLOB STATS. */
    for (i = 0; i < NUM_OF_PRINTABLE_CHAR; ++i)
        global_sd->char_statistics[i] += sd->char_statistics[i];

    /* Add the number of bytes read by this threads to the global counter. */
    global_n_bytes_read += n_bytes_read;

    /* Release (unlock) mutex. */
    if (!pthread_mutex_unlock(&lock)) {
        exit(-1);

    }
    /* Exit threads. */
    pthread_exit(NULL);
}


int main(int argc, char const *argv[]) {
    pthread_t thread[NUM_THREADS];
    struct sockaddr_in serv_addr = {0}, cli_addr;
    int connfd, n_of_thread;
    socklen_t addrsize = sizeof(struct sockaddr_in);


    /* Register signal handler for SIGINT signal. (Ctrl-C pressed)
       Structure to pass to the registration syscall */
    struct sigaction new_action;
    memset(&new_action, 0, sizeof(new_action));
    /* Assign pointer to our handler function */
    new_action.sa_handler = (__sighandler_t) my_signal_handler;
    /* Setup the flags */
    new_action.sa_flags = SA_SIGINFO;

    if (0 != sigaction(SIGINT, &new_action, NULL)) {
        report_error("Signal handle registration failed");
        return -1;
    }


    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT_NUM);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listenfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)))
        report_error("Failed to bind to socket");
    if (listen(listenfd, NUM_THREADS))
        report_error("Failed to listen to socket");

    /* Create and initialize statistics global data structure (GLOB STATS).*/
    global_sd = (StatisticsData *) malloc(sizeof(StatisticsData));

    /* Initialize the global counter of total bytes read. (An integer)*/
    global_n_bytes_read = 0;

    /* Create and initialize data mutex.*/
    if (!pthread_mutex_init(&lock, NULL)) {
        report_error("Failed to initialize mutex");
        free(global_sd);
        return -1;
    }

    /* Listen to port 2233 in an infinite loop.*/
    n_of_thread = 0;
    exit_flag = 0;
    while (1) {
        connfd = accept(listenfd, (struct sockaddr *) &cli_addr, &addrsize);
        if (connfd < 0) {
            report_error("Failed to accept socket");
            pthread_mutex_destroy(&lock);
            free(global_sd);
            exit(-1);
        }

        /* Upon connection accepted - start a Client Processor threads, continue listening. */
        if (!pthread_create(&thread[n_of_thread++],
                            NULL,
                            start_client_thread,
                            (void *) connfd)) {
            report_error("Failed to create threads");
            free(global_sd);
            pthread_mutex_destroy(&lock);
            pthread_exit(NULL);
        }
        if (exit_flag) { break; }
    }
    pthread_mutex_destroy(&lock);
    return 0;
}