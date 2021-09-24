FROM python:3
ADD vinspect.py /
# TODO: add snyk CLI
ADD https://github.com/snyk/snyk/releases/download/v1.720.0/snyk-linux /usr/bin/snyk 
# TODO: set env vars

CMD [ "python", "./vinspect.py" ]