#include <stdio.h>
#include <string.h> /* for strlen(), strdup() */
#include <stdlib.h> /* for free() */
#include <unistd.h> /* for getopt() */
#include <ctype.h>  /* for isdigit() */
#include <errno.h>

#include "aarray.h"
#include "data-reader.h"

#define LINE_MAX    128

/**
 * Load the assocArray of attribute value entries
 */
static int
loadAssociativeArray(AssociativeArray *assocArray, char *filename, int useIntKey)
{
    char linebuffer[LINE_MAX];
    char *strkey = NULL, *value = NULL;
    int nEntries = 0;
    int intkey;
    FILE *fp = NULL;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: Failed to open input file '%s' : %s",
                filename, strerror(errno));
        return -1;
    }

    while (readDataLine(fp, linebuffer, LINE_MAX, &strkey, &value) > 0) {
        //printf("STRKEY: %s\nVALUE: %s\n", strkey, value);
        if (useIntKey && isdigit(strkey[0])) {
            if (sscanf(strkey, "%d", &intkey) != 1) {
                fprintf(stderr, "Error: Failed extracting integer from '%s'\n", strkey);
                return -1;
            }
            if (aaInsert(assocArray,
                        (AAKeyType) &intkey, sizeof(int),
                        strdup(value)) < 0) {
                fprintf(stderr, "Failed to add key '%d' to assocArray\n", intkey);
                return -1;
            }
        } else {

            if (aaInsert(assocArray,
                        (AAKeyType) strkey, strlen(strkey),
                        strdup(value)) < 0) {
                fprintf(stderr, "Failed to add key '%s' to assocArray\n", strkey);
                return -1;
            }
        }
        nEntries++;
    }

    fclose(fp);
    return nEntries;
}

/**
 * Query the array with all the values in the given file
 */
static int
queryAssociativeArray(AssociativeArray *assocArray, char *filename, int useIntKey)
{
    char linebuffer[LINE_MAX];
    char *strkey = NULL, *value = NULL;
    int intkey;
    FILE *fp = NULL;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: Failed to open query input file '%s' : %s",
                filename, strerror(errno));
        return -1;
    }

    while (readPlainLine(fp, linebuffer, LINE_MAX, &strkey)) {
        if (useIntKey && isdigit(strkey[0])) {
            if (sscanf(strkey, "%d", &intkey) != 1) {
                fprintf(stderr, "Error: Failed extracting integer from '%s'\n", strkey);
                return -1;
            }

            value = aaLookup(assocArray, (AAKeyType) &intkey, sizeof(int));
            if (value == NULL) {
                printf("LOOKUP: key (%d) produced no value\n", intkey);
            } else {
                printf("LOOKUP: key (%d) produced value '%s'\n", intkey, value);
            }

        } else {
            value = aaLookup(assocArray, (AAKeyType) strkey, strlen(strkey));
            if (value == NULL) {
                printf("LOOKUP: key '%s' produced no value\n", strkey);
            } else {
                printf("LOOKUP: key '%s' produced value '%s'\n", strkey, value);
            }
        }
    }

    fclose(fp);
    return 1;
}

/**
 * Delete the selected values from the array.  Note that we free the values
 * as otherwise they are memory leaks as we are managing the memory for
 * these values outside of the library
 */
static int
deleteFromAssociativeArray(AssociativeArray *assocArray, char *filename, int useIntKey)
{
    char linebuffer[LINE_MAX];
    char *strkey = NULL, *value = NULL;
    int intkey;
    FILE *fp = NULL;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: Failed to open query input file '%s' : %s",
                filename, strerror(errno));
        return -1;
    }

    while (readPlainLine(fp, linebuffer, LINE_MAX, &strkey)) {
        if (useIntKey && isdigit(strkey[0])) {
            if (sscanf(strkey, "%d", &intkey) != 1) {
                fprintf(stderr, "Error: Failed extracting integer from '%s'\n", strkey);
                return -1;
            }

            value = aaDelete(assocArray, (AAKeyType) &intkey, sizeof(int));
            if (value == NULL) {
                printf("DELETE: key (%d) produced no value\n", intkey);
            } else {
                printf("DELETE: key (%d) produced value '%s'\n", intkey, value);
                free(value);
            }

        } else {
            value = aaDelete(assocArray, (AAKeyType) strkey, strlen(strkey));
            if (value == NULL) {
                printf("DELETE: key '%s' produced no value\n", strkey);
            } else {
                printf("DELETE: key '%s' produced value '%s'\n", strkey, value);
                free(value);
            }
        }
    }

    fclose(fp);
    return 1;
}


static int
deleteValue(AAKeyType key, size_t keylen, void *value, void *userdata)
{
    if (value != NULL)  free(value);
    return 0;
}

#define DEFAULT_ARRAY_SIZE  100
#define OPTIONLEN   10

/** print out the help */
void usage(char *progname)
{
    fprintf(stderr, "%s [<OPTIONS>] <datafile> [ <datafile> ... ]\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Creates an associative array and loads it with values from\n");
    fprintf(stderr, "the data files given.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options: \n");
    fprintf(stderr, "%-*s: Print this help.\n", OPTIONLEN, "-h");
    fprintf(stderr, "%-*s: If a key is made of digits, store it as an int.\n", OPTIONLEN, "-i");
    fprintf(stderr, "%-*s: Size of table used internally, default %d.\n",
            OPTIONLEN, "-n <SIZE>", DEFAULT_ARRAY_SIZE);
    fprintf(stderr, "%-*s: Output file to write to, default stdout.\n",
            OPTIONLEN, "-o <FILE>");
    fprintf(stderr, "%-*s: Print out the table after processing.\n", OPTIONLEN, "-p");
    fprintf(stderr, "%-*s: Hash using the given algorithm.  Choices are \"sum\", \"length\",\n",
            OPTIONLEN, "-H <ALG>");
    fprintf(stderr, "%-*s: or your own algorithm.\n", OPTIONLEN, "");
    fprintf(stderr, "%-*s: Probe using the given algorithm.  Choices are \"linear\", \"quadratic\",\n",
            OPTIONLEN, "-P <ALG>");
    fprintf(stderr, "%-*s: or \"doublehash\".\n", OPTIONLEN, "");
    fprintf(stderr, "%-*s: Perform queries on all of the keys listed in <FILE> (one per line)\n",
            OPTIONLEN, "-q <FILE>");
    fprintf(stderr, "%-*s: Delete all of the keys listed in <FILE> (one per line)\n",
            OPTIONLEN, "-d <FILE>");
    fprintf(stderr, "\n");
    fprintf(stderr, "The order of the operations controlled by -d, -q and -p are: deletion first,\n");
    fprintf(stderr, "followed by any queries, and then finally printing (if indicated)\n");
    fprintf(stderr, "\n");
    exit (1);
}

/**
 * Program mainline -- loads all data from files listed into the hash.
 * Uses getopt(3) to parse arguments.
 */
int
main(int argc, char **argv)
{
    char *programname = NULL;
    FILE *ofp = stdout;
    int arraySize = DEFAULT_ARRAY_SIZE;
    int useIntKey = 0;
    int printContents = 0;
    char *queryfile = NULL, *deletefile = NULL;
    int i, c;

    AssociativeArray *assocArray;
    char *hash1 = "sum", *hash2 = "len", *probe = "lin";

    /* save program name before calling getopt() */
    programname = argv[0];

    /** use getopt(3) to parse command line */
    while ((c = getopt(argc, argv, "hpin:o:P:H:2:q:d:")) != -1) {
        if (c == 'i') {
            useIntKey = 1;
        } else if (c == 'p') {
            printContents = 1;
        } else if (c == 'n') {
            if (sscanf(optarg, "%d", &arraySize) != 1) {
                fprintf(stderr,
                        "Error: cannot parse assocArray size requested from '%s'\n",
                        optarg);
                usage(programname);
            }

        } else if (c == 'H') {
            hash1 = optarg;

        } else if (c == '2') {
            hash2 = optarg;

        } else if (c == 'P') {
            probe = optarg;

        } else if (c == 'q') {
            queryfile = optarg;

        } else if (c == 'd') {
            deletefile = optarg;

        } else if (c == 'o') {
            ofp = fopen(optarg, "w");
            if (ofp == NULL) {
                fprintf(stderr,
                        "Error: cannot open requested output file '%s' : %s\n",
                        optarg, strerror(errno));
                usage(programname);
            }

        } else if (c == 'h') {
            usage(programname);
        }
    }

    /** update argc + argv to skip past flags */
    argc -= optind;
    argv += optind;

    if (argc < 1) {
        fprintf(stderr, "Error: No data files listed to load!\n");
        usage(programname);
    }

    /** allocate the array and fail out if we cannot */
    assocArray = aaCreateAssociativeArray(arraySize, probe, hash1, hash2);
    if (assocArray == NULL) {
        fprintf(stderr, "Error: cannot allocate associative array - exitting\n");
        return -1;
    }
    //printf("RANDOM: %s\n", (*assocArray).hashNamePrimary);

    /** getopt leaves us only "file" arguments left in argv */
    for (i = 0; i < argc; i++) {
        if (loadAssociativeArray(assocArray, argv[i], useIntKey) < 0) {
            fprintf(stderr, "Error: failed loading from file '%s'\n", argv[i]);
            return -1;
        }
    }
    printf("Associative array loaded\n");


    /** delete anything that we were asked to */
    if (deletefile != NULL) {
        deleteFromAssociativeArray(assocArray, deletefile, useIntKey);
    }

    /** perform any queries we were asked to */
    if (queryfile != NULL) {
        queryAssociativeArray(assocArray, queryfile, useIntKey);
    }

    /* print out what we loaded */
    aaPrintSummary(ofp, assocArray);
    if (printContents) {
        aaPrintContents(ofp, assocArray, "  ");
    }

    /* clean up before exit */
    aaIterateAction(assocArray, deleteValue, NULL);
    aaDeleteAssociativeArray(assocArray);

    /* exit with success if we get here */
    return 0;
}