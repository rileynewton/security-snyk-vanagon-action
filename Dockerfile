FROM python:latest
ADD vinspect.py /usr/local/bin/vinspect
RUN chmod 751 /usr/local/bin/vinspect
# add snyk
RUN apt update
#RUN apk add libstdc++
ADD https://github.com/snyk/snyk/releases/download/v1.720.0/snyk-linux /usr/local/bin/snyk 
RUN chmod 751 /usr/local/bin/snyk 
# add ruby and vanagon
RUN apt install ruby -y
RUN apt install ruby-bundler -y
RUN gem install fustigit
RUN gem install git
RUN gem install docopt
RUN gem install vanagon
# TEMP
#RUN mkdir -p /home/runner/work/foo/bar
#ADD ./testfiles/test_runtime /home/runner/work/foo/bar
# RUN the script
CMD [ "vinspect" ]