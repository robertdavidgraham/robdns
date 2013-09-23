#ifndef ZONEFILE_TRACKER_H
#define ZONEFILE_TRACKER_H

struct Tracker
{
	FILE *fp;
	const char *filename;
	unsigned line_number;
	unsigned offset;
	unsigned length;
	uint64_t bytes_read;
	uint64_t bytes_reported;
    uint64_t file_size;
	clock_t when_reported;
};

void
tracker_report(struct Tracker *tracker, size_t len);

uint64_t
tracker_get_filesize(struct Tracker *tracker, const char *filename);


#endif
