delete:
	-docker rm ssva
build:
	docker build -t ssva .
run:
	docker run -e INPUT_SNYKTOKEN=$(SNYK_TOKEN) \
		-e INPUT_SNYKORG=sectest \
		-e GITHUB_WORKSPACE=/home/runner/work/foo/bar \
		-e INPUT_SKIPPROJECTS=agent-runtime-5.5.x,agent-runtime-1.10.x,client-tools-runtime-irving,pdk-runtime \
		-e INPUT_SKIPPLATFORMS=cisco-wrlinux-5-x86_64,cisco-wrlinux-7-x86_64,debian-10-armhf,eos-4-i386,fedora-30-x86_64,fedora-31-x86_64,osx-10.14-x86_64 \
		--name ssva -t ssva

all:
	make delete 
	make build 
	make run