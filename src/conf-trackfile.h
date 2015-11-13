#ifndef CONF_TRACKFILE_H
#define CONF_TRACKFILE_H

struct Conf_TrackFile *conf_trackfile_create(void);
void conf_trackfile_destroy(struct Conf_TrackFile *tf);

/**
 * Keep track of the configuration file (name, time, size), and every
 * sub-configuration file that's been added through the "include" 
 * statement
 */
void conf_trackfile_add(struct Conf_TrackFile *tf, const char *filename);

/**
 * @return the number of files we are current tracking. This is for
 * enumerating the files.
 */
unsigned conf_trackfile_count(const struct Conf_TrackFile *tf);

/**
 * @return the indexed filename, where 'index' must be less than the total
 * count of files we are tracking. This is a simple accessor function for 
 * enumerating the files in our list.
 */
const char *conf_trackfile_filename(const struct Conf_TrackFile *tf, unsigned index);

/**
 * During the processing of a SIGHUP, test the new list of configuration
 * files in order to see if they have changed. If not, then we can
 * skip reconfiguration
 */
unsigned
conf_trackfile_has_changed(const struct Conf_TrackFile *tf);

#endif
