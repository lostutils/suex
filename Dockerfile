# FROM snapcore/snapcraft
FROM ubuntu:17.10

RUN apt update

RUN apt install -y \
         clang \
         cmake \
         make \
         libpam-dev \
         libdw-dev \
         ruby-ronn g++ \
         rpm \
         direnv

RUN apt install -y apt-utils 
RUN apt install -y git
RUN apt install -y snapcraft
RUN apt install -y vim
RUN apt install -y python3.6
RUN apt install -y curl 
RUN curl https://bootstrap.pypa.io/get-pip.py | python3.6
RUN pip install virtualenv
RUN apt install -y clang-tidy
RUN apt install -y ruby-ronn 
ADD entrypoint.sh /entrypoint.sh
ENTRYPOINT /entrypoint.sh
