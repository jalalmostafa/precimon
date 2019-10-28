#define VERSION 30
#define PROTOCOL_VERSION 12

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 64 * 1024 /* larger = more efficient */
#define ERROR      42
#define LOG        44

#define SECRET_LENGTH 256
char local_secret[SECRET_LENGTH] = {"Oxdeadbeef"};
char injector_command[4096] = {"/usr/local/bin/injector.py"};

int en[94] = {
 8, 85, 70, 53, 93, 72, 61,  1, 41, 36,
49, 92, 44, 42, 25, 58, 81, 15, 57, 10,
54, 60, 12, 45, 43, 91, 22, 86, 65,  9,
27, 18, 37, 39,  2, 68, 46, 71,  6, 79,
76, 84, 59, 75, 82,  4, 48, 55, 64,  3,
 7, 56, 40, 73, 77, 69, 88, 13, 35, 11,
66, 26, 52, 78, 28, 89, 51,  0, 30, 50,
34,  5, 32, 21, 14, 38, 19, 29, 24, 33,
47, 31, 80, 16, 83, 90, 67, 23, 20, 17,
74, 62, 87, 63 };


int de[94] = {
67,  7, 34, 49, 45, 71, 38, 50,  0, 29,
19, 59, 22, 57, 74, 17, 83, 89, 31, 76,
88, 73, 26, 87, 78, 14, 61, 30, 64, 77,
68, 81, 72, 79, 70, 58,  9, 32, 75, 33,
52,  8, 13, 24, 12, 23, 36, 80, 46, 10,
69, 66, 62,  3, 20, 47, 51, 18, 15, 42,
21,  6, 91, 93, 48, 28, 60, 86, 35, 55,
 2, 37,  5, 53, 90, 43, 40, 54, 63, 39,
82, 16, 44, 84, 41,  1, 27, 92, 56, 65,
85, 25, 11,  4 };

void mixup(char *s)
{
    int i;
    for (i = 0; s[i]; i++) {
        if(s[i] <= ' ')
            continue;
        if(s[i] > '~')
            continue;

        s[i] = en[s[i] - 33] + 33;
    }
}

void unmix(char *s)
{
    int i;
    for (i = 0; s[i]; i++) {
        if(s[i] <= ' ')
            continue;
        if(s[i] >  '~')
            continue;

        s[i] = de[s[i] - 33] + 33;
    }
}

void logger(int type, char *s1, char *s2, int number)
{
    time_t now;
    int fd ;
    char logbuffer[BUFSIZE * 2];
    char* s;

    time(&now);
    s = ctime(&now);
    s[strlen(s) - 1] = 0; /* remove tailing newline */

    switch (type) {
    case ERROR:
        sprintf(logbuffer,"%s ERROR: %s:%s:%d\n",s, s1, s2, number);
        break;
    case LOG:
        sprintf(logbuffer,"%s  INFO: %s:%s:%d\n",s, s1, s2, number);
        break;
    }

    if((fd = open("precimon_collector.log", O_CREAT| O_WRONLY | O_APPEND, 0644)) >= 0) {
        if (write(fd, logbuffer, strlen(logbuffer)) != (ssize_t)strlen(logbuffer)) {
            printf("Logfile: opened but failed to write\n");
            exit(99);
        }

        close(fd);
    }

    if(type == ERROR)
        exit(3);
}

void identify(size_t read, char* printbuffer, char* buffer, char* preamble, char* name, char* hostname,
                char* utc, char* remote_secret,
                char* version, char* postamble)
{
    size_t j;

    buffer[read]=0; /* terminate the buffer */
    unmix(buffer);
    for(j = 0; j < read - 1; j++) { /* check for illegal parent directory use .. */
        if(buffer[j] == '.' && buffer[j+1] == '.') {
            logger(ERROR, "Parent directory (..) path names not supported character-position", buffer, j);
        }

        if(buffer[j] == '\\') {
            logger(ERROR, "Parent directory (\\) path names not supported character-position", buffer, j);
        }
    }

    read = sscanf(buffer, "%s %s %s %s %s %s %s", preamble, name, hostname, utc, remote_secret, version, postamble);
    sprintf(printbuffer, "New Request name=%s, hostname=%s, utc=%s, precimon-version=%s\n", name, hostname, utc, version);
    logger(LOG, printbuffer, "starting ...", 0);

    if(read != 7) {
        logger(ERROR, "Badly formed request returned=:", buffer, read);
    }

    if(!isalnum(hostname[0])) /* alphabetic or number */
        logger(ERROR, "Badly formed hostname start char", hostname, hostname[0]);

    for(j = 0; j < strlen(hostname); j++) {
        if(!isalnum(hostname[j]))
        /* hostname[j] = '_'; replace non-digit or letter with underscore */
            if(hostname[j] == '.')
                hostname[j] = 0; /* replace fullstop with END of name */
    }

    for(j = 0; j < strlen(utc); j++) {
        if(utc[j] == '-' || utc[j] == ':' || utc[j] == 'T' )
            continue;

        if(!isdigit(utc[j]))
            utc[j] = '_'; /* replace non-digit with underscore */
    }

    /* no checks for preamble and postamble as they are random */
    if(strncmp(utc, "201", 3) ) /* works until 2020 year */
        logger(ERROR, "Missing year in request", buffer, -1);

    if(strncmp(remote_secret, local_secret, sizeof(local_secret)) )
        logger(ERROR, "Missing remote_secret in request", buffer, -1);

    if(strncmp(version, "12", 2) )
        logger(ERROR, "Missing version in request", buffer, -1);
}

/* this is a child precimon_collector server process, so we can exit on errors */
void child(int fd, FILE *pop, int save_json)
{
    int json_file_fd, bytes;
    int loops = 0;
    long ret;
    char buffer[BUFSIZE + 1];
    char printbuffer[BUFSIZE + 1];

    char preamble[256];
    char name[256];
    char hostname[256];
    char utc[256];
    char remote_secret[SECRET_LENGTH];
    char version[256];
    char postamble[256];

    memset(buffer, 0, BUFSIZE + 1);
    memset(printbuffer, 0, BUFSIZE + 1);

    ret = read(fd, buffer, BUFSIZE); /* read Web request in one go */
    if(ret == 0 || ret == -1) { /* read failure stop now */
        logger(ERROR, "Failed to read browser request, read() returned 0 or -1", "errno=", errno);
    }

    identify(ret, printbuffer, buffer, preamble, name, hostname, utc, remote_secret, version, postamble);

    /* open the file for writing to save the JSON data*/
    if(save_json) {
        sprintf(printbuffer, "%s-%s.json", hostname, utc);
        if((json_file_fd = open(printbuffer, O_CREAT | O_WRONLY, 0644)) == -1) {
            logger(ERROR, "Failed to open file for writing, returned", hostname, json_file_fd);
        }
        logger(LOG, "opened", buffer, -1);
    } else{
        logger(LOG, "not opening the JSON output file as requested", buffer, -1);
    }

    do {
        ret = read(fd, buffer, BUFSIZE);

        if(ret > 0) {
            loops++;
            if(save_json) {
                /*logger(LOG, "Bytes read from socket, returned bytes",hostname,ret);*/
                if((bytes = write(json_file_fd, buffer, ret)) == -1) {
                    logger(LOG, "Failed to write JSON file, errno", hostname, errno);
                    logger(ERROR, "Failed to write JSON file, bytes", hostname, bytes);
                }
            }

            if(pop) {
                if((bytes = fwrite(buffer, 1, ret, pop)) != ret) {
                    logger(LOG, "failed to write to injector, errno", hostname, errno);
                    logger(LOG, "failed to write to injector, bytes", hostname, bytes);
                    pop = NULL; /* stop writing */
                }
                fflush(pop);
            }
        }
    } while(ret > 0);

    logger(LOG, "Finished loops", hostname, loops);
    exit(1);
}

void hint(char *command)
{
    printf(
    "hint: %s -p port -d directory [ -t protocol ] [ -i ] [ -X secret ] [ -c injector_command ] -n\n"
    "or\n"
    "hint: %s -a collector.conf\n"
    "precimon Collector version=%d protocol=%d\n\n"
    "Do not mix the -a option with the command line options\n"
    "\tprecimon_collector daemon saves precimon output files\n"
    "\tExample: precimon_collector -p 8181 -d /home/nigel\n"
    "\tExample: precimon_collector -p 8181 -d /home/sally -i -X abcd1234\n"
    "\tExample: precimon_collector -p 8181 -d /home/janet -i -X beetlejuice -c /home/janet/injector_for_DB42.py -n\n\n"
    "\tDefault is just saving the file to the supplied directory based on hostname+date+time.json\n\n"
    "\tWith the -i option is also pipes the data to an injector to a stats database\n"
    "\t    You need to place a suitable injector for your stats database at %s (default).\n"
    "\t    Override the full pathname of the injector with the -c option. Normally a Python program.\n\n"
    "\tYou can set the shared secret (password or phrase) with the -X secret option.\n"
    "\t    Or set this to the PRECIMON_SECRET shell variable.\n\n"
    "\tIf using an injector then you can switch off saving to a JSON file with:\n"
    "\t    -n\n\n"
    "\tThis program disconnects from the terminal to run in the background.\n\n"
    "\tcollector.conf contents should be like this:\n\n"
    "\t\tport=8181\n"
    "\t\tdirectory=/home/nag/precimondata\n"
    "\t\tsecret=abc123\n"
    "\t\tinject=1\n"
    "\t\tinjector=/usr/local/bin/precimon_for_linux_to_InfluxDB_injector_30.py\n"
    "\t\tjson=1\n"
    "Note: for inject and json options: 1=on and 0=off\n\n"
    "\tNo warranty given or implied\n"
    "\tJalal Mostafa<jalalmostafa22@gmail.com>"
    "\tModified version of Nigel Griffiths<nigelargriffiths@hotmail.com> NJMON Collector\n",
        command, command, VERSION, PROTOCOL_VERSION, injector_command);
    exit(0);
}

void interrupt(int signum)
{
    int child_pid;
    int waitstatus;
    if (signum == SIGUSR2) {
        while ((child_pid = wait(&waitstatus)) != -1) {
            /* retry for last child process */
        }
        exit(0);
    }
    signal(SIGUSR2, interrupt);
}

void run_injector(int injector, int port, FILE** pop) {
    if(injector) {
        logger(LOG, "Starting injector part1", injector_command, getpid());
        logger(LOG, "Starting injector part2", "port", port);
        errno = 0;

        if((*pop = popen(injector_command, "w")) == NULL) {
            logger(LOG, "popen injector FAILED continue without injection", "errno=", errno);
            *pop = NULL;
        }
    }
}

int main(int argc, char **argv)
{
    char buffer[4465];
    int port = -1;
    int injector = 0;
    int save_json = 1;
    int ch;
    int i, pid, listenfd, socketfd, hit;
    int line = 0;
    char *s;
    char *directory = 0;
    char *filename = 0;
    FILE *pop = NULL;
    FILE *fp = NULL;

    socklen_t length;
    static struct sockaddr_in cli_addr; /* static = initialised to zeros */
    static struct sockaddr_in serv_addr; /* static = initialised to zeros */

    s = getenv("PRECIMON_SECRET");
    if(s != 0)
        strncpy(local_secret, s, SECRET_LENGTH);

    while (-1 != (ch = getopt(argc, argv, "h?p:d:c:X:ina:"))) {
        switch (ch) {
        case 'h':
        case '?':
            hint(argv[0]);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'd':
            directory = optarg;
            break;
        case 'c':
            strncpy(injector_command, optarg, 4095);
            if(access(injector_command, X_OK) == -1) {
                sprintf(buffer, "ERROR: injector command %s is not executable", injector_command);
                printf("%s\n", buffer);
                logger(ERROR, buffer, "getopt", 13);
            }
            break;
        case 'n':
            save_json = 0;
            break;
        case 'i':
            injector = 1;
            break;
        case 'X':
            strncpy(local_secret, optarg, SECRET_LENGTH - 1);
            break;
        case 'a':
            filename = optarg;
            if((fp = fopen(filename, "r")) == NULL) {
                printf("Failed to fopen(\"%s\", \"r+\")\n", filename);
                exit(99);
            }

            while(fgets(buffer, 4096 - 1, fp) != NULL) {
                line++;
                buffer[strlen(buffer) - 1] = 0;

                if(strncmp("port=", buffer, strlen("port=")) == 0) {
                    if(sscanf(&buffer[5], "%d", &port) != 1)
                        printf("duff port number line=%d line=%s\n",line,buffer);
                }

                if(strncmp("directory=", buffer, strlen("directory=")) == 0) {
                    directory = (char*)malloc(strlen(buffer));
                    strcpy(directory, &buffer[strlen("directory=")]);
                }

                if(strncmp("secret=", buffer, strlen("secret=")) == 0) {
                    if(sscanf(&buffer[7], "%s", local_secret) != 1)
                        printf("duff local_secret\n");
                }

                if(strncmp("inject=", buffer, strlen("inject=")) == 0) {
                    if(sscanf(&buffer[7], "%d", &injector) != 1)
                        printf("duff inject\n");
                }

                if(strncmp("injector=", buffer, strlen("injector=")) == 0) {
                    if(sscanf(&buffer[9], "%s", injector_command) != 1)
                        printf("duff injector_command\n");
                }

                if(strncmp("json=", buffer, strlen("json=")) == 0) {
                    if(sscanf(&buffer[5], "%d", &save_json) != 1)
                        printf("duff json\n");
                }
            }
            fclose(fp);
            break;
        default:
            sprintf(buffer, "Unexpected command parameter \"%c\" = 0x%x - bailing out", (char)ch, ch);
            printf("%s\n", buffer);
            logger(ERROR, buffer, "getopt", 12);
            break;
        }
    }

    if(port == -1) {
        sprintf(buffer, "mandatory -p port option missing");
        printf("%s\n", buffer);
        logger(ERROR, buffer, "opt check", 14);
    }

    if(port < 0 || port > 60000) {
        printf("Invalid port number %d(try 1->60000)", port);
        logger(ERROR, "Invalid port number (try 1->60000)", "port check", port);
    }

    if(directory == NULL) {
        sprintf(buffer, "Mandatory -d directory option missing\n");
        printf("%s\n", buffer);
        logger(ERROR, buffer, "opt check", 15);
    }

    if(!strncmp(directory, "/"   , 2 ) || !strncmp(directory, "/etc", 5) ||
       !strncmp(directory, "/bin", 5 ) || !strncmp(directory, "/lib", 5) ||
       !strncmp(directory, "/tmp", 5 ) || !strncmp(directory, "/usr", 5) ||
       !strncmp(directory, "/dev", 5 ) || !strncmp(directory, "/sbin", 6)){
        sprintf(buffer, "Bad top directory %s, see precimon_collector -?", directory);
        printf("%s\n", buffer);
        logger(ERROR, buffer, "directory check", 16);
    }

    if(!save_json && !injector) {
        sprintf(buffer, "Bad combination = don't save JSON and no injector = nothing to do!");
        printf("%s\n", buffer);
        logger(ERROR, buffer, "opt check", 17);
    }

#ifdef CHROOT
    if(chroot(directory) == -1){  /* best security but can't run python */
#else
    if(chdir(directory) == -1){   /* lets hope the user account is secure */
#endif
        sprintf(buffer, "can't change to directory %s", directory);
        printf("%s\n", buffer);
        logger(ERROR, buffer, "opt check directory valid", 18);
    }
    /* Become deamon + unstopable and no zombies children (= no wait()) */
    if(fork() != 0)
        return 0; /* parent returns OK to shell */

    signal(SIGCLD, SIG_IGN); /* ignore child death */
    signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */
    signal(SIGUSR2, interrupt);

    /* close open files */
    for(i = 0; i < 32; i++)
        close(i);

    /* break away from process group */
    setpgrp();
    sprintf(buffer,
    "Starting port=%d directory=\"%s\" inject=%d injector-cmd=\"%s\" JSON=%d secret=\"%s\" Collector Version=%d",
    port, directory, injector, injector_command, save_json, local_secret, PROTOCOL_VERSION);

    logger(LOG, buffer, directory, port);
    /* setup the network socket */
    if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        logger(ERROR, "System call", "socket", errno);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if(bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        logger(ERROR, "System call", "bind", errno);

    if(listen(listenfd, 64) < 0)
        logger(ERROR, "System call", "listen", errno);

    for(hit = 1;; hit++) {
        length = sizeof(cli_addr);

        if((socketfd = accept(listenfd, (struct sockaddr*) &cli_addr, &length)) < 0)
            logger(ERROR, "System call", "accept", errno);

        if((pid = fork()) < 0) {
            /* parent but fork failed - bail out */
            logger(ERROR, "System call", "fork", pid);
        } else {
            /* child */
            if(pid == 0) {
                close(listenfd);
                run_injector(injector, port, &pop);
                child(socketfd, pop, save_json); /* never returns */
            } else {
                /* parent */
                close(socketfd);
            }
        }
    }
}
