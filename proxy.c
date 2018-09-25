/*
 * COMP 321 Project 6: Web Proxy
 *
 * This program implements a multithreaded HTTP proxy.
 *
 * Lusia Lu (ll45) and Robbie Foley (rrf2)
 */

#include <assert.h>
#include <pthread.h>

#include "csapp.h"


#define NUM_THREADS 1


typedef struct {
	struct client_info **buf;
	int n;
	int front; int rear;
	int item_count;
	pthread_mutex_t lock;
	pthread_cond_t empty;
	pthread_cond_t full;
} sbuf_t;


struct producer_info {
	int listenfd;
	sbuf_t *sbuf;
};

struct consumer_info {
	FILE *log_file;
	sbuf_t *sbuf;
};

struct client_info {
	int clientfd;
	struct sockaddr_in clientaddr;
};



static void	client_error(int fd, const char *cause, int err_num,
		    const char *short_msg, const char *long_msg);
static char    *create_log_entry(const struct sockaddr_in *sockaddr,
		    const char *uri, int size);
static int	parse_uri(const char *uri, char **hostnamep, char **portp,
		    char **pathnamep);
static int 	open_listen(int port);
static int	open_client(char *hostname, int port);

static char *read_request(int client_connfd, char** methodp, char **urip, char** httpstringp);

static void forward_request(int server_connfd, char *headers,
	char *path, char *httpstring);

static int read_and_forward_reply(int server_connfd, int client_connfd);

static void sbuf_init(sbuf_t *sp, int n);

static void sbuf_destroy(sbuf_t *sp);

static void sbuf_insert(sbuf_t *sp, struct client_info *item);

static struct client_info *sbuf_remove(sbuf_t *sp);

static void *consumer_routine(void *vargp);

static void *producer_routine(void *vargp);


/*
 * Requires:
 *   <to be filled in by the student(s)>
 *
 * Effects:
 *   <to be filled in by the student(s)>
 */
int
main(int argc, char **argv)
{

	//compareStrings()

	/* Check the arguments. */
	if (argc != 2) {
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}

	/* Declare local variables. */
	FILE *log_file;
	int port, listenfd;
	sbuf_t *sbuf;


	/* Open the log file. */
	log_file = fopen("proxy.log", "w");

	port = atoi(argv[1]);

	listenfd = open_listen(port);
	if (listenfd < 0)
		unix_error("open_listen error");

	/* Set SIGPIPE handler. */
	signal(SIGPIPE, SIG_IGN);

	sbuf = Malloc(sizeof(sbuf));
	sbuf_init(sbuf, 16);

	struct producer_info *producer_infop = &(struct producer_info){listenfd, sbuf};


	pthread_t consumer_threads[NUM_THREADS];

	struct consumer_info *consumer_infop = &(struct consumer_info){log_file, sbuf};

	for (int i = 0; i < NUM_THREADS; i++) {
		Pthread_create(&consumer_threads[i], NULL, consumer_routine, consumer_infop);
	}

	// pthread_t producer_thread;
	// Pthread_create(&producer_thread, NULL, producer_routine, producer_infop);
	producer_routine(producer_infop);
	while(1);

	sbuf_destroy(sbuf);
	Free(sbuf);
}

static void *
producer_routine(void *vargp) {

	Pthread_detach(Pthread_self());

	struct producer_info info = *(struct producer_info *)vargp;
	sbuf_t *sbuf = info.sbuf;
	int listenfd = info.listenfd;


	socklen_t clientlen;
	struct sockaddr_in clientaddr;
	int client_connfd;

	clientlen = sizeof(clientaddr);

	while (1) {
		fprintf(stderr, "%s\n", "-----------------------");
		if ((client_connfd = accept(listenfd, (struct sockaddr*)&clientaddr,
			&clientlen)) == -1) {
			exit(0);
		}

		struct client_info *info = Malloc(sizeof(struct client_info));
		info->clientfd = client_connfd;
		info->clientaddr = clientaddr;

		sbuf_insert(sbuf, info);
	}

}


static void *
consumer_routine(void *vargp) {

	Pthread_detach(Pthread_self());

	struct consumer_info info = *(struct consumer_info *)vargp;

	FILE *log_file = info.log_file;
	sbuf_t *sbuf = info.sbuf;

	socklen_t clientlen;
	struct sockaddr_in clientaddr;
	int client_connfd, server_connfd;
	char chaddrp[INET_ADDRSTRLEN], client_host_name[NI_MAXHOST];
	char *method, *uri, *httpstring, *headers;
	char *end_host_name, *end_port, *end_path;
	int response_size;
	char *new_log;


	while (1) {
		struct client_info *cinfo = sbuf_remove(sbuf);

		client_connfd = cinfo->clientfd;
		clientaddr = cinfo->clientaddr;
		clientlen = sizeof(clientaddr);

		Free(cinfo);

		/*
		 * Call Accept() to accept a pending connection request from
		 * the browswer, and create a new file descriptor representing
		 * the server's end of the connection.  Assign the new file
		 * descriptor to client_connfd.
		 */


		int x;


		// Use getnameinfo() to determine the client's host name.
		if ((x = getnameinfo((struct sockaddr*)&clientaddr, clientlen, client_host_name,
			NI_MAXHOST, chaddrp, INET_ADDRSTRLEN, 0)) != 0) {
			fprintf(stderr, "%s\n", gai_strerror(x));
			unix_error("getnameinfo error");
		}



		/*
		 * Convert the binary representation of the client's IP
		 * address to a dotted-decimal string.
		 */
		Inet_ntop(AF_INET, &clientaddr.sin_addr, chaddrp,
		    INET_ADDRSTRLEN);
		printf("Connected to client: %s (%s)\n", client_host_name, chaddrp);



		headers = read_request(client_connfd, &method, &uri, &httpstring);

		if (strcmp(method, "GET") != 0) {
			continue;
		}


		if (parse_uri(uri, &end_host_name, &end_port, &end_path) == -1) {
			unix_error("parse_uri error");
			// client_error(clientfd, uri, 502, "Proxy error", "Cannot parse uri")
			// return;
		}


		server_connfd = open_client(end_host_name, atoi(end_port));
		if (server_connfd == -1) {
			unix_error("open_clientfd Unix error");
		} else if (server_connfd == -2) {
			dns_error("open_clientfd DNS error");
		}


		forward_request(server_connfd, headers, end_path, httpstring);


		response_size = read_and_forward_reply(server_connfd, client_connfd);


		/* Open the log file. */
		new_log = create_log_entry(&clientaddr, uri, response_size);

		fprintf(log_file, "%s\n", new_log);

		// Close the server's end of the connection.
		Close(client_connfd);
	}

	/* Return success. */
	fclose(log_file);
	return NULL;
}


static char*
read_request(int client_connfd, char **methodp, char **urip, char **httpstringp)
{

	//fprintf(stderr, "%s\n", "READING REQUEST");

	rio_t rio;
	size_t n;
	char buf[MAXLINE];
	char uri[MAXLINE];// = buf;
	char httpstring[MAXLINE];
	char method[MAXLINE];
	//char *ptr;
	//int uri_len = 0;
	int i = -1;
	// struct header_list *headers; = Malloc(sizeof (struct header_list*));
	// struct header_list *header = headers;
	char *headers = Malloc(MAXLINE);
	//fprintf(stderr, "%d\n", MAXLINE);
	strcpy(headers, "");

	Rio_readinitb(&rio, client_connfd);
	n = rio_readlineb(&rio, buf, MAXLINE);

	//fprintf(stderr, "%s\n", "CLIENT REQUEST:");


	while(strcmp(buf, "\r\n")) {

		if (n == MAXLINE) {
			fprintf(stderr, "\n\n\nMAXLINE\n\n\n");
		}

		//fprintf(stderr, "%s", buf);

		/* Reading uri. */
		if (i == -1) {

			//fprintf(stderr, "REQUEST LINE: %s\n", buf);

			sscanf(buf, "%s %s %s", method, uri, httpstring);

			*methodp = method;
			*urip = uri;
			*httpstringp = httpstring;


		} else if (strncmp("Connection", buf, 10) != 0 &&
			strncmp("Keep-Alive", buf, 10) != 0 &&
			strncmp("Proxy-Connection", buf, 16) != 0) {
			//fprintf(stderr, "%s\n", "ADDING CONNECTION CLOSE");
			strncat(headers, buf, n);
		}

		i ++;
		n = rio_readlineb(&rio, buf, MAXLINE);
	}
	//strcat(headers, "Connection: close\r\n\r");
	strcat(headers, "Connection: close\r\n");


	//fprintf(stderr, "headers: %s\n", headers);
	return headers;
}

static void
forward_request(int server_connfd, char *headers, char *path,
	char *httpstring)
{
	//fprintf(stderr, "%s\n", "FORWARDING REQUEST");
	int request_len = 9 + strlen(path) + strlen(httpstring) + strlen(headers);
	char request[request_len];
	strcpy(request, "GET ");
	strcat(request, path);
	strcat(request, " ");
	strcat(request, httpstring);
	strcat(request, "\r\n");
	strcat(request, headers);
	strcat(request, "\r\n");
	if (rio_writen(server_connfd, request, request_len) < 0) {
		fprintf(stderr, "%s\n", "rio_writen < 0");
		// client_error(clientfd, uri, 504, "Gateway Timeout", "Cannot recognize host name or host port");
		// close(server_connfd);
		// return;
	}
	//fprintf(stderr, "\nFORWARDED REQUEST:\n%s", request);
	(void) headers;
}

static int
read_and_forward_reply(int server_connfd, int client_connfd) {

	fprintf(stderr, "%s\n", "Forwarding reply");

	rio_t rio;
	size_t n;
	char buf[MAXLINE];
	int size = 0;


	Rio_readinitb(&rio, server_connfd);
	//fprintf(stderr, "%s\n", "Initialized rio");

	while ((n = rio_readlineb(&rio, buf, MAXLINE)) != 0) {
		if ((int)n < 0) {
			fprintf(stderr, "%s\n", "rio_readlineb < 0");
		}
		size += n;
		if (n == MAXLINE) {
			fprintf(stderr, "\n\n\nMAXLINE\n\n\n");
		}
		if (rio_writen(client_connfd, buf, n) == -1) {
			fprintf(stderr, "%s\n", "rio_writen == -1");
		};
	}

	fprintf(stderr, "\n%s\n", "finished forwarding");
	return size;
}


/*
 * Requires:
 *   port is an unused TCP port number.
 *
 * Effects:
 *   Opens and returns a listening socket on the specified port.  Returns -1
 *   and sets errno on a Unix error.
 */
static int
open_listen(int port)
{
	struct sockaddr_in serveraddr;
	int listenfd, optval;

	// Prevent an "unused parameter" warning.  REMOVE THIS STATEMENT!
	(void)port;
	// Set listenfd to a newly created stream socket.
	if ((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		unix_error("socket error");
	}

	// Eliminate "Address already in use" error from bind().
	optval = 1;
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
	    (const void *)&optval, sizeof(int)) == -1)
		return (-1);
	memset(&serveraddr, 0, sizeof(serveraddr));
	/*
	 * Set the IP address in serveraddr to the special ANY IP address, and
	 * set the port to the input port.  Be careful to ensure that the IP
	 * address and port are in network byte order.
	 */

	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	serveraddr.sin_addr = (struct in_addr){htonl(INADDR_ANY)};

	// Use bind() to set the address of listenfd to be serveraddr.
	if (bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) != 0) {
		unix_error("bind error");
	}

	/*
	 * Use listen() to ready the socket for accepting connection requests.
	 * Set the backlog to 8.
	 */
	if (listen(listenfd, 8) != 0) {
		unix_error("listen error");
	}

	return (listenfd);
}

/*
 * Requires:
 *   The parameter "uri" must point to a properly NUL-terminated string.
 *
 * Effects:
 *   Given a URI from an HTTP proxy GET request (i.e., a URL), extract the
 *   host name, port, and path name.  Create strings containing the host name,
 *   port, and path name, and return them through the parameters "hostnamep",
 *   "portp", "pathnamep", respectively.  (The caller must free the memory
 *   storing these strings.)  Return -1 if there are any problems and 0
 *   otherwise.
 */
static int
parse_uri(const char *uri, char **hostnamep, char **portp, char **pathnamep)
{
	fprintf(stderr, "%s\n", "Parsing uri");
	const char *pathname_begin, *port_begin, *port_end;

	if (strncasecmp(uri, "http://", 7) != 0)
		return (-1);

	/* Extract the host name. */
	const char *host_begin = uri + 7;
	const char *host_end = strpbrk(host_begin, ":/ \r\n");
	if (host_end == NULL)
		host_end = host_begin + strlen(host_begin);
	int len = host_end - host_begin;
	char *hostname = Malloc(len + 1);
	strncpy(hostname, host_begin, len);
	hostname[len] = '\0';
	*hostnamep = hostname;

	/* Look for a port number.  If none is found, use port 80. */
	if (*host_end == ':') {
		port_begin = host_end + 1;
		port_end = strpbrk(port_begin, "/ \r\n");
		if (port_end == NULL)
			port_end = port_begin + strlen(port_begin);
		len = port_end - port_begin;
	} else {
		port_begin = "80";
		port_end = host_end;
		len = 2;
	}
	char *port = Malloc(len + 1);
	strncpy(port, port_begin, len);
	port[len] = '\0';
	*portp = port;

	/* Extract the path. */
	if (*port_end == '/') {
		pathname_begin = port_end;
		const char *pathname_end = strpbrk(pathname_begin, " \r\n");
		if (pathname_end == NULL)
			pathname_end = pathname_begin + strlen(pathname_begin);
		len = pathname_end - pathname_begin;
	} else {
		pathname_begin = "/";
		len = 1;
	}
	char *pathname = Malloc(len + 1);
	strncpy(pathname, pathname_begin, len);
	pathname[len] = '\0';
	*pathnamep = pathname;

	return (0);
}


/*
 * Requires:
 *   hostname points to a string representing a host name, and port in an
 *   integer representing a TCP port number.
 *
 * Effects:
 *   Opens a TCP connection to the server at <hostname, port> and returns a
 *   file descriptor ready for reading and writing.  Returns -1 and sets
 *   errno on a Unix error.  Returns -2 on a DNS (getaddrinfo) error.
 */
static int
open_client(char *hostname, int port)
{
	fprintf(stderr, "%s\n", "Opening client");
	struct sockaddr_in serveraddr;
	struct addrinfo *ai;
	int clientfd;


	// Set clientfd to a newly created stream socket.

	if ((clientfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		unix_error("socket error");
	}

	int x;

	// Use getaddrinfo() to get the server's IP address.
	if ((x = getaddrinfo(hostname, NULL, NULL, &ai)) != 0) {
		client_error(clientfd, gai_strerror(x), 404, "", "");
	}

	/*
	 * Set the address of serveraddr to be server's IP address and port.
	 * Be careful to ensure that the IP address and port are in network
	 * byte order.
	 */
	memset(&serveraddr, 0, sizeof(serveraddr));
	memcpy(&serveraddr, ai->ai_addr, ai->ai_addrlen);
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);

	if (connect(clientfd, (struct sockaddr *) &serveraddr, ai->ai_addrlen) == -1) {
		unix_error("connect error");
	}

	return (clientfd);
}





/*
 * Requires:
 *   The parameter "sockaddr" must point to a valid sockaddr_in structure.  The
 *   parameter "uri" must point to a properly NUL-terminated string.
 *
 * Effects:
 *   Returns a string containing a properly formatted log entry.  This log
 *   entry is based upon the socket address of the requesting client
 *   ("sockaddr"), the URI from the request ("uri"), and the size in bytes of
 *   the response from the server ("size").
 */
static char *
create_log_entry(const struct sockaddr_in *sockaddr, const char *uri, int size)
{
	struct tm result;

	/*
	 * Create a large enough array of characters to store a log entry.
	 * Although the length of the URI can exceed MAXLINE, the combined
	 * lengths of the other fields and separators cannot.
	 */
	const size_t log_maxlen = MAXLINE + strlen(uri);
	char *const log_str = Malloc(log_maxlen + 1);

	/* Get a formatted time string. */
	time_t now = time(NULL);
	int log_strlen = strftime(log_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z: ",
	    localtime_r(&now, &result));

	/*
	 * Convert the IP address in network byte order to dotted decimal
	 * form.
	 */
	Inet_ntop(AF_INET, &sockaddr->sin_addr, &log_str[log_strlen],
	    INET_ADDRSTRLEN);
	log_strlen += strlen(&log_str[log_strlen]);

	/*
	 * Assert that the time and IP address fields occupy less than half of
	 * the space that is reserved for the non-URI fields.
	 */
	assert(log_strlen < MAXLINE / 2);

	/*
	 * Add the URI and response size onto the end of the log entry.
	 */
	snprintf(&log_str[log_strlen], log_maxlen - log_strlen, " %s %d", uri,
	    size);

	return (log_str);
}

/*
 * Requires:
 *   The parameter "fd" must be an open socket that is connected to the client.
 *   The parameters "cause", "short_msg", and "long_msg" must point to properly
 *   NUL-terminated strings that describe the reason why the HTTP transaction
 *   failed.  The string "short_msg" may not exceed 32 characters in length,
 *   and the string "long_msg" may not exceed 80 characters in length.
 *
 * Effects:
 *   Constructs an HTML page describing the reason why the HTTP transaction
 *   failed, and writes an HTTP/1.0 response containing that page as the
 *   content.  The cause appearing in the HTML page is truncated if the
 *   string "cause" exceeds 2048 characters in length.
 */
static void
client_error(int fd, const char *cause, int err_num, const char *short_msg,
    const char *long_msg)
{
	char body[MAXBUF], headers[MAXBUF], truncated_cause[2049];

	assert(strlen(short_msg) <= 32);
	assert(strlen(long_msg) <= 80);
	/* Ensure that "body" is much larger than "truncated_cause". */
	assert(sizeof(truncated_cause) < MAXBUF / 2);

	/*
	 * Create a truncated "cause" string so that the response body will not
	 * exceed MAXBUF.
	 */
	strncpy(truncated_cause, cause, sizeof(truncated_cause) - 1);
	truncated_cause[sizeof(truncated_cause) - 1] = '\0';

	/* Build the HTTP response body. */
	snprintf(body, MAXBUF,
	    "<html><title>Proxy Error</title><body bgcolor=""ffffff"">\r\n"
	    "%d: %s\r\n"
	    "<p>%s: %s\r\n"
	    "<hr><em>The COMP 321 Web proxy</em>\r\n",
	    err_num, short_msg, long_msg, truncated_cause);

	/* Build the HTTP response headers. */
	snprintf(headers, MAXBUF,
	    "HTTP/1.0 %d %s\r\n"
	    "Content-type: text/html\r\n"
	    "Content-length: %d\r\n"
	    "\r\n",
	    err_num, short_msg, (int)strlen(body));

	/* Write the HTTP response. */
	if (rio_writen(fd, headers, strlen(headers)) != -1)
		rio_writen(fd, body, strlen(body));
}

/* Create an empty, bounded, shared FIFO buffer with n slots. */
static void
sbuf_init(sbuf_t *sp, int n) {
	sp->buf = Calloc(n, sizeof(struct client_info));
	sp->n = n;
	sp->front = sp->rear = 0;
	sp->item_count = 0;
	Pthread_mutex_init(&sp->lock, NULL);
	Pthread_cond_init(&sp->empty, NULL);
	Pthread_cond_init(&sp->full, NULL);
	fprintf(stderr, "%p\n", &sp->lock);
	fprintf(stderr, "%p\n", &sp->full);
	fprintf(stderr, "%p\n", &sp->empty);
}

static void
sbuf_destroy(sbuf_t *sp) {
	fprintf(stderr, "%s\n", "DESTROYING");
	Free(sp->buf);
	Pthread_mutex_destroy(&sp->lock);

	/* DESTROY THE CONDITION VARIABLES HERE. */
	Pthread_cond_destroy(&sp->empty);
	Pthread_cond_destroy(&sp->full);
}

static void
sbuf_insert(sbuf_t *sp, struct client_info *item) {
	fprintf(stderr, "%s\n", "locking lock insert1");
	fprintf(stderr, "count: %d\n", sp->item_count);

	Pthread_mutex_lock(&sp->lock);
	fprintf(stderr, "%s\n", "locking lock insert2");
	while (sp->item_count == sp->n) {
		Pthread_cond_wait(&sp->full, &sp->lock);
	}
	sp->buf[(++sp->rear)%(sp->n)] = item;
	fprintf(stderr, "%s\n", "locking lock insert3");
	fprintf(stderr, "%p\n", &sp->lock);
	fprintf(stderr, "%p\n", &sp->full);
	fprintf(stderr, "%p\n", &sp->empty);
	Pthread_cond_signal(&sp->empty);
	sp->item_count ++;

	fprintf(stderr, "%s\n", "locking lock insert4");
	Pthread_mutex_unlock(&sp->lock);
	fprintf(stderr, "%s\n", "locking lock insert5");
}

static struct client_info *
sbuf_remove(sbuf_t *sp) {
	fprintf(stderr, "%s\n", "locking lock remove1");
	struct client_info *item;

	fprintf(stderr, "%p\n", &sp->lock);
	fprintf(stderr, "%p\n", &sp->full);
	fprintf(stderr, "%p\n", &sp->empty);

	Pthread_mutex_lock(&sp->lock);
	fprintf(stderr, "%s\n", "locking lock remove2");
	fprintf(stderr, "count: %d\n", sp->item_count);
	while (sp->item_count == 0) {
		Pthread_cond_wait(&sp->empty, &sp->lock);
	}
	fprintf(stderr, "%s\n", "locking lock remove3");
	item = sp->buf[(++sp->front)%(sp->n)];
	Pthread_cond_signal(&sp->full);
	sp->item_count --;
	fprintf(stderr, "%s\n", "locking lock remove4");
	Pthread_mutex_unlock(&sp->lock);
	fprintf(stderr, "%s\n", "locking lock remove5");
	return item;
}

