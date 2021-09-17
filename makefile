
virus: virus.asm
	mkdir -p bin/
	python3 ascii.py payload.txt > art.asm
	fasm virus.asm bin/virus
	chmod +x bin/virus
	gcc -o bin/static_test -static test.c
	gcc -o bin/pie_test -fPIC -pie test.c
	go build -o bin/gobin hello.go
	rustc hello.rs -o bin/rustbin
	cp /bin/ls bin/

all: virus

test: virus
	./run_tests.sh

clean: 
	rm -rf bin/*
