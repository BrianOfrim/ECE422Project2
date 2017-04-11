JAVA_HOME = /usr/lib/jvm/java

make:
	javac *.java
	javah Encryption
	gcc -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -shared -fpic -o libencrypt.so lib_encrypt.c
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.
