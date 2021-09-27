delete:
	docker rm ssva
build:
	docker build -t ssva .
run:
	docker run -e INPUT_SNYKTOKEN=$SNYK_TOKEN \
		-e INPUT_SNYKORG=sectest \
		-e GITHUB_WORKSPACE=/home/runner/work/foo/bar \
		-e INPUT_SKIPPROJECTS=agent-runtime-5.5.x,agent-runtime-1.10.x,client-tools-runtime-irving,pdk-runtime \
		--name ssva -t ssva