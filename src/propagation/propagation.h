#ifndef PROPAGATION_H
#define PROPAGATION_H

#include <sys/queue.h>

struct entry {
    char *path;
    STAILQ_ENTRY(entry) link;
};
STAILQ_HEAD(queue, entry);

int propagation(struct queue *files);
int free_queue(struct queue *q);
int print_files(struct queue *files);

#endif /* PROPAGATION_H */
