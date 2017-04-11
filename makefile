JAVA_HOME = /usr/lib/jvm/java

make:
	javac *.java
	javah Encryption Decryption
	gcc -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -shared -fpic -o libencrypt.so lib_encrypt.c
	gcc -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -shared -fpic -o libdecrypt.so lib_decrypt.c
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.
