#include <stdio.h>
#include <stdlib.h>
#include <jni.h>
#include "Encryption.h"

void encrypt (int *v, int *k);
JNIEXPORT jbyteArray JNICALL Java_Encryption_encrypt
(JNIEnv *env, jobject object, jbyteArray data, jbyteArray key){
	printf("Entered the c function\n");
	jsize lenData;
	jsize lenKey;
	jbyte *myCopyData;
	jbyte *myCopyKeys;
	jboolean *is_copy_data = 0;
	jboolean *is_copy_key = 0;
	
	lenData = (*env)->GetArrayLength(env, data);
	lenKey = (*env)->GetArrayLength(env, key);

	myCopyData = (jbyte *) (*env)->GetByteArrayElements(env, data, is_copy_data);
    if (myCopyData == NULL){
        printf("Cannot obtain data array from JVM\n");
        exit(0);
    }

	myCopyKeys = (jbyte *) (*env)->GetByteArrayElements(env, key, is_copy_key);
    if (myCopyData == NULL){
        printf("Cannot obtain key array from JVM\n");
        exit(0);
    }
    int * keyarr = (int*) myCopyKeys;
    int * datarr = (int*) myCopyData;
    //printf("key 0: %d\n",keyarr[0]);
    //printf("key 1: %d\n",keyarr[1]);
    //printf("key 2: %d\n",keyarr[2]);
    //printf("key 3: %d\n",keyarr[3]);

    int i = 0;
    //printf("number of bytes ints: %d\n",lenData);
    int numInts = lenData/4;
    //printf("number of ints: %d\n",numInts);
    //printf("number of ints calculated: %d\n",(sizeof(datarr)/sizeof(datarr[0])));
    for(i = 0; i < numInts/2;i++){
        //printf("current i val: %d\n", i);
        encrypt(&datarr[i*2] , keyarr);

    }
    //printf("made it passed the loop\n");
    jbyteArray returnByteArray = (*env)-> NewByteArray(env, lenData);
    (*env)->SetByteArrayRegion(env, returnByteArray,0, lenData,myCopyData);
    //printf("made it passed the assignment\n");
	
    return (jbyteArray) returnByteArray;

}

void encrypt (int *v, int *k){
/* TEA encryption algorithm */
	unsigned int y = v[0], z=v[1], sum = 0;
	unsigned int delta = 0x9e3779b9, n=32;

	while (n-- > 0){
		sum += delta;
		y += (z<<4) + k[0] ^ z + sum ^ (z>>5) + k[1];
		z += (y<<4) + k[2] ^ y + sum ^ (y>>5) + k[3];
	}

	v[0] = y;
	v[1] = z;
}

