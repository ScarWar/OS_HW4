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


#define report_error(str) printf("LINE: %d, Error - %s, %s\n", __LINE__, (str), strerror(errno))
#define DEFAULT_SOURCE "/dev/urandom"
#define BUFFER_SIZE 2048
#define NUM_OF_PRINTABLE_CHAR 95
#define PORT_NUM 2233
#define min(s, t) ((s) < (t) ? (s) : (t))


int main(int argc, char const *argv[]) {
    int inputfd, sockfd, total_sent;
    long LEN;
    long long n_bytes_read, read_buffer_size, n_bytes_sent,
            n_bytes_recv;
    char *output_buffer = NULL, *input_buffer = NULL;

    struct sockaddr_in dest_addr = {0};

    if (argc != 2) {
        printf("LINE: %d, Error - Invalid number of arguments, expected 2\n", __LINE__);
        return -1;
    }
    /* Read the length (in bytes) of the stream to process */
    LEN = strtol(argv[1], NULL, 10);
    if (ERANGE == errno) {
        report_error("Unable to convert string to integer");
        return -1;
    }
    /* Open a socket to Server on your local machine, port 2233 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        report_error("Socket creation failed");
        return -1;
    }

    /* Set parameters of socket connection */
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT_NUM);
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);


    /* Connect to Server */
    if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0) {
        report_error("Failed to connect to server");
        return -1;
    }
	
    /* Open /dev/urandom for reading */
    if ((inputfd = open(DEFAULT_SOURCE, O_RDONLY)) < 0) {
        report_error("Failed to open input file");
        if (close(sockfd) < 0)
            report_error("Failed to close socket");
        return -1;
    }	


    /* Transfer (write) LEN bytes from /dev/urandom to Server through the socket.
     * Send LEN to Server
     */
    total_sent = 0;
    while (total_sent < sizeof(int)) {
        n_bytes_sent = write(sockfd, (&LEN) + total_sent, sizeof(int) - total_sent);
        if (n_bytes_sent < 0) {
            report_error("Failed to send LEN to server");
            if (close(sockfd) < 0)
                report_error("Failed to close socket");
            if (close(inputfd) < 0)
                report_error("Failed to close data stream");
            return -1;
        }
        if (n_bytes_sent == 0){
        	break;
        }
        total_sent += n_bytes_sent;
    }

    output_buffer = (char *) malloc(BUFFER_SIZE);
    if (!output_buffer) {
        report_error("Memory allocation failed");
        if (close(sockfd) < 0)
            report_error("Failed to close socket");
        if (close(inputfd) < 0)
            report_error("Failed to close data stream");
        return -1;
    }

    /* Read from input than send to server */
    while (LEN > 0) {

        total_sent = 0;
        read_buffer_size = (ssize_t)min(LEN, BUFFER_SIZE);
        n_bytes_read = read(inputfd, 
        	output_buffer, 
        	(size_t) read_buffer_size);
        
        /* If n_bytes_read < 0 handle error */
        if (n_bytes_read < 0) {
            report_error("Failed to read from input file");
            if (close(sockfd) < 0)
                report_error("Failed to close socket");
            if (close(inputfd) < 0)
                report_error("Failed to close data stream");
            free(output_buffer);
            return -1;
        }
		/* Update number of bytes left to send*/
        LEN -= n_bytes_read;

        /* Send buffer to server */
        while (n_bytes_read > 0) {
            n_bytes_sent = send(
                    sockfd,                     // Socket file descriptor
                    output_buffer + total_sent, // Offset
                    (size_t) n_bytes_read, 0);  // number of bytes left to send

            if (n_bytes_sent < 0) {
                report_error("Failed to send to server");
                if (close(sockfd) < 0)
                    report_error("Failed to close socket");
                if (close(inputfd) < 0)
                    report_error("Failed to close data stream");
                free(output_buffer);
                return -1;
            }
            /* Update number of bytes left to send */
            n_bytes_read -= n_bytes_sent;
            total_sent += n_bytes_sent;

        }
    }
	free(output_buffer);

    /* Get (read) the result from Server through the socket */
    int total_read = 0;
    int printable_bytes;

    while (total_read < sizeof(int)) {

        n_bytes_recv = read(
        	sockfd,
	        (&printable_bytes) + total_read,
	        sizeof(int) - total_read);
        if (n_bytes_recv < 0) {
            report_error("Failed to read from server");
            return -1;
        }
        total_read += (int)n_bytes_recv;
    }

    /* Print the result */
    printf("The number of printable bytes is %d\n", printable_bytes);

    /* Close descriptors */
    if (close(inputfd) < 0) {
        report_error("Failed to close input file");
        return -1;
    }

    /* Close socket*/
    if (close(sockfd) < 0) {
        report_error("Failed to close socket");
        return -1;
    }

    /* Quit */
    return 0;
}
