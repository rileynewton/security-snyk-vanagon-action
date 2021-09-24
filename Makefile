delete:
	docker rm ssva
build:
	docker build -t ssva .
run:
	docker run -e INPUT_SNYKTOKEN=$SNYK_TOKEN \
		-e INPUT_SNYKORG=sectest \
		-e GITHUB_WORKSPACE=/home/runner/work/foo/bar \
		--name ssva -t ssva