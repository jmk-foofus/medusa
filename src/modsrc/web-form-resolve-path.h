#ifndef __MEDUSA_WEB_FORM_RESOLVE_PATH_H__
#define __MEDUSA_WEB_FORM_RESOLVE_PATH_H__

/**
 * Module for string based pathname resolution. Maps string sections to a list
 * by splitting on the '/' character. The root and the relative target are
 * concatenated after the list is walked and its values evaluated. On '..',
 * remove a node and move back. On '.', do nothing. Otherwise, append a node.
 * The process is repeated until the end of the list.
 *
 * An unoptimised version of the code was benchmarked at 120M resolutions/sec
 * for compiled-in strings.
 */

/**
 *
 */
char * resolvePath(char * x, char * y);

#endif //__MEDUSA_WEB_FORM_RESOLVE_PATH_H__
