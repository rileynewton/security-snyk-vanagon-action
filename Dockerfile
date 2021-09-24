FROM python:latest
ADD vinspect.py /
# add snyk
RUN apk update
RUN apk add libstdc++
ADD https://github.com/snyk/snyk/releases/download/v1.720.0/snyk-linux /usr/local/bin/snyk 
RUN chmod 751 /usr/local/bin/snyk 
# add ruby and vanagon
RUN apk add ruby
RUN apk add ruby-bundler
RUN gem install fustigit
RUN gem install git
RUN gem install docopt
RUN gem install vanagon
# TEMP
RUN mkdir -p /home/runner/work/foo/bar
ADD test_runtime/* /home/runner/work/foo/bar
# RUN the script
CMD [ "python", "./vinspect.py" ]