#include <stdio.h>
#include <stdlib.h>
#include <jni.h>

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

	myCopyData = (jbyte *) (*env)->GetIntArrayElements(env, data, is_copy_data);
    if (is_copy_data == NULL){
        printf("Cannot obtain data array from JVM\n");
        exit(0);
    }

	myCopyKeys = (jbyte *) (*env)->GetIntArrayElements(env, key, is_copy_key);
    if (is_copy_key == NULL){
        printf("Cannot obtain key array from JVM\n");
        exit(0);
    }

	


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

