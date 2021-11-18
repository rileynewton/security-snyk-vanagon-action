FROM ubuntu:focal
RUN apt update
RUN apt upgrade -y
# install dependencies
RUN apt install -y ruby ruby-bundler ruby-dev git build-essential
RUN gem install fustigit
RUN gem install git
RUN gem install docopt
RUN git clone https://github.com/puppetlabs/vanagon.git && cd vanagon && bundle install && gem build -o vanagon.gem vanagon.gemspec && gem install --local ./vanagon.gem
# move over the executables
ADD https://github.com/puppetlabs/security-snyk-vanagon-action/releases/latest/download/vanagon_action /usr/local/bin/vanagon_action
RUN chmod +x /usr/local/bin/vanagon_action
# install snyk
ADD https://github.com/snyk/snyk/releases/download/v1.720.0/snyk-linux /usr/local/bin/snyk 
RUN chmod 751 /usr/local/bin/snyk
# startup script and startup
RUN env DEBIAN_FRONTEND=noninteractive apt install nginx -y
ADD docker_confs/nginx_config /
ADD docker_confs/start_script.sh /usr/local/bin/start_script.sh
RUN chmod +x /usr/local/bin/start_script.sh
CMD ["start_script.sh"]