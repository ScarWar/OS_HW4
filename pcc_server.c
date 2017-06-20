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

#define report_error(str) printf("LINE: %d, Error - %s, %s\n", __LINE__, (str), strerror(errno))
#define BUFFER_SIZE 2048
#define NUM_OF_PRINTABLE_CHAR 95
#define PORT_NUM 2233
#define min(s, t) ((s) < (t) ? (s) : (t))

typedef struct statistics_data_t {
    long long char_statistics[NUM_OF_PRINTABLE_CHAR];
} StatisticsData;

static StatisticsData global_sd;
static long long global_n_bytes_read = 0;
static int listenfd;
static global_n_thread_alive;
static global_n_thread_dead;
pthread_mutex_t lock;
char exit_flag;


void my_signal_handler(int signum, siginfo_t *info, void *ptr) {
    int i = 0;
    /* Stop listening the port. Close the socket. */
    close(listenfd);

    /* Wait for all running threads to finish. */
    while(0 < global_n_thread_alive && i < 10){
    	usleep(100000);
    	++i;
    }

    if(0 < global_n_thread_dead){
    	printf("Error occured during the run of some threads\n");
    } else {
	    /* Print the global bytes counter. */
	    printf("\nThe number of bytes read by server is %lld\n", global_n_bytes_read);

	    /* Print the global statistics. */
	    printf("we saw ");
	    for (i = 0; i < NUM_OF_PRINTABLE_CHAR; ++i) {
	        printf("%lld '%c'", global_sd.char_statistics[i], i + 32);
	        if (i == NUM_OF_PRINTABLE_CHAR - 1) {
	        	printf("\n");
	            break;
	        }
	        printf(", ");
	    }
	}
    /* Exit process. */
    pthread_mutex_destroy(&lock);
    exit(0);

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
    long long n_bytes_read = 0, n_bytes_recv = 0, total_read = 0, total_sent = 0, n_bytes_sent, n_bytes_to_read;
    int i, LEN = 0, n_printable_bytes;
    char buf[BUFFER_SIZE] = {0};
    
    /* Create a statistics local data structure. */
    int sockfd = *((int *) arg);
    StatisticsData sd;

    /*
    Read the content from the socket. For every byte:
        - Increment the number of bytes read.
        - Decide whether it is printable or not.
        - If it is, then update the local statistics.
    */
    while (total_read < sizeof(int)) {
        n_bytes_recv = read(
        	sockfd, 
        	&LEN + total_sent, 
        	sizeof(int) - total_sent);
        if (n_bytes_recv < 0) {
            report_error("Failed to read from client");
            __sync_fetch_and_add(&global_n_thread_dead, 1);
            return NULL;
        }
        total_read += n_bytes_recv;
    }

    n_bytes_read = 0;    
    while (n_bytes_read < LEN) {
        
        n_bytes_to_read = min(LEN - n_bytes_read, BUFFER_SIZE);
        n_bytes_recv = read(
        	sockfd, 
        	buf, 
        	(size_t) (n_bytes_to_read));

        if (n_bytes_recv < 0) {
            report_error("Failed to read from socket");
            __sync_fetch_and_add(&global_n_thread_dead, 1);
            return NULL;
        }
        if (count_printable(buf, (int) n_bytes_recv, &sd)) {
        	__sync_fetch_and_add(&global_n_thread_dead, 1);
            return NULL;
        }
        n_bytes_read += n_bytes_recv;
    }

    /* Send the number of the printable bytes back to the client. */
    n_printable_bytes = 0;
    for (i = 0; i < NUM_OF_PRINTABLE_CHAR; ++i)
        n_printable_bytes += (int)sd.char_statistics[i];

    total_sent = 0;
    while (total_sent < sizeof(int)) {

        n_bytes_sent = write(
        	sockfd, 
        	(&n_printable_bytes) + total_sent,
        	sizeof(int) - total_sent);

        if (n_bytes_sent < 0) {
            report_error("Failed to send to server");
            if (close(sockfd) < 0)
                report_error("Failed to close socket");
            __sync_fetch_and_add(&global_n_thread_dead, 1);
            return NULL;
        }
        total_sent += n_bytes_sent;
    }


    /* Close the connection. */
    close(sockfd);
    /* Acquire (lock) mutex. */
    if (pthread_mutex_lock(&lock)) {
    	report_error("Failed to lock mutex");
    	__sync_fetch_and_add(&global_n_thread_dead, 1);
        return NULL;
    }

    /* Add local statistics to GLOB STATS. */
    for (i = 0; i < NUM_OF_PRINTABLE_CHAR; ++i)
        global_sd.char_statistics[i] += sd.char_statistics[i];

    /* Add the number of bytes read by this threads to the global counter. */
    global_n_bytes_read += n_bytes_read;

    /* Update number of threads*/
    __sync_fetch_and_add(&global_n_thread_alive, -1);

    /* Release (unlock) mutex. */
    if (pthread_mutex_unlock(&lock)) {
		report_error("Failed to unlock mutex");
		__sync_fetch_and_add(&global_n_thread_dead, 1);
        return NULL;

    }
    /* Exit threads. */
    pthread_exit(NULL);
}


int main(int argc, char const *argv[]) {
    struct sockaddr_in serv_addr = {0}, cli_addr;
    int *connfd, n_of_thread, i;
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

    if (bind(listenfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) {
        report_error("Failed to bind to socket");
        return -1;
    }

    if (listen(listenfd, 10)) {
        report_error("Failed to listen to socket");
        return -1;
    }


    /* Create and initialize statistics global data structure (GLOB STATS).*/
    for(i = 0; i< NUM_OF_PRINTABLE_CHAR; ++i)
    	global_sd.char_statistics[i] = 0;

    /* Initialize the global counter of total bytes read. (An integer)*/
    global_n_bytes_read = 0;

    /* Create and initialize data mutex.*/
    if (pthread_mutex_init(&lock, NULL)) {
        report_error("Failed to initialize mutex");
        return -1;
    }
	
    /* Listen to port 2233 in an infinite loop.*/
    while (1) {
		connfd = (int*) malloc(sizeof(int));
		if (!connfd){
			report_error("Memory allocation failed");
			continue;
		}

        *connfd = accept(listenfd, NULL, NULL);
        if (*connfd < 0) {
            report_error("Failed to accept socket");
            pthread_mutex_destroy(&lock);
            exit(-1);
        }

        /* Upon connection accepted - start a Client Processor threads, continue listening. */
        pthread_t thread;
        if (pthread_create(
        	&thread,
            NULL,
            start_client_thread,
            (void *) connfd)
            ) {
            report_error("Failed to create threads");
        	close(*connfd);
            free(connfd);
            pthread_mutex_destroy(&lock);
            continue;
        } else {
        	__sync_fetch_and_add(&global_n_thread_alive, 1);
        }
    }
    return 0;
}
