#ifndef	__ASSOCIATIVE_ARRAY_TOOLS_HEADER__
#define	__ASSOCIATIVE_ARRAY_TOOLS_HEADER__

#include <stdio.h>

typedef unsigned char *AAKeyType;
typedef size_t AAIndexType;

/**
 * The type used for the array itself.
 *
 * Under the policy of "information hiding" we show
 * the "user code" only the minimum amount of information
 * required to use our tools.  Implementation details
 * are all hidden away inside of our "library" of code
 */
typedef struct AssociativeArray AssociativeArray;

/** creator and destructor for the associative array */
AssociativeArray *aaCreateAssociativeArray(
			size_t size,
			char *probingStrategyl,
			char *primaryHashAlgorithm,
			char *secondaryHashAlgorithm
		);
void aaDeleteAssociativeArray(AssociativeArray *array);

int aaIterateAction(
		AssociativeArray *array,
		int (*userfunction)(AAKeyType key, size_t keylen, void *datavalue, void *userdata),
		void *userdata);

/** the interface to do the critical work: insert, delete and lookup */
int aaInsert(AssociativeArray *array,
		AAKeyType key, size_t keylength,
		void *value);
void *aaLookup(AssociativeArray *array, AAKeyType key, size_t keylength);
void *aaDelete(AssociativeArray *array, AAKeyType key, size_t keylength);

/** print out the data, prefixing each line with the lineLeader */
void aaPrintContents(FILE *fp, AssociativeArray *array, char *lineLeader);
void aaPrintSummary(FILE *fp, AssociativeArray *array);

#endif
