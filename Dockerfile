FROM python:alpine
ADD vinspect.py /
# TODO: add snyk CLI
RUN apk add libstdc++
ADD https://github.com/snyk/snyk/releases/download/v1.720.0/snyk-linux /usr/local/bin/snyk 
RUN chmod 751 /usr/local/bin/snyk 
# TEMP
RUN mkdir -p /home/runner/work/foo/bar
ADD test_runtime /home/runner/work/foo/bar
# RUN the script
CMD [ "python", "./vinspect.py" ]