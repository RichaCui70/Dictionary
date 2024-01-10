#ifndef	__HASHING_TOOLS_HEADER__
#define	__HASHING_TOOLS_HEADER__

#include <stdio.h>

#include <aarray.h>

typedef size_t HashIndex;

// forward declaration of typedef to allow it to be used in the
// definition of HashProbe and allow HashProbe to be used in AssociativeArray
typedef struct AssociativeArray AssociativeArray;

typedef HashIndex (*HashAlgorithm)(AAKeyType key, size_t keyLength, HashIndex tableSize);
typedef HashIndex (*HashProbe)(struct AssociativeArray *table, AAKeyType key, size_t keyLength, int startIndex, int, int *cost);

typedef struct KeyDataPair {
	AAKeyType key;
	size_t keylen;
	void *value;
	int validity;
} KeyDataPair;

struct AssociativeArray {
	KeyDataPair *table;
	int size;
	int nEntries;
	HashProbe hashProbe;
	char *probeName;
	HashAlgorithm hashAlgorithmPrimary;
	char *hashNamePrimary;
	HashAlgorithm hashAlgorithmSecondary;
	char *hashNameSecondary;
	int searchCost;
	int insertCost;
	int deleteCost;
};


#define	HASH_EMPTY		0
#define	HASH_USED		1
#define	HASH_DELETED	2

/** prototypes */
HashIndex hashByLength(AAKeyType key, size_t keyLength, HashIndex size);
HashIndex hashBySum(AAKeyType key, size_t keyLength, HashIndex tableSize);
HashIndex hashByNut(AAKeyType key, size_t keyLength, HashIndex tableSize);
HashIndex linearProbe(AssociativeArray *table, AAKeyType key, size_t keyLength, int index, int stopOnInvalid, int *cost);
HashIndex  quadraticProbe(AssociativeArray *table, AAKeyType key, size_t keyLength, int index, int stopOnInvalid, int *cost);
HashIndex  doubleHashProbe(AssociativeArray *table, AAKeyType key, size_t keyLength, int index, int stopOnInvalid, int *cost);

int getLargerPrime(int value);

int doKeysMatch(AAKeyType key1, size_t key1len, AAKeyType key2, size_t key2len);
int printableKey(char *buffer, int bufferlen, AAKeyType key, size_t keylen);

#endif
