FROM python:2.7

WORKDIR /crawler

RUN apt-get update
RUN apt-get install apt-transport-https

RUN echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | tee /etc/apt/sources.list.d/iovisor.list
RUN apt-get update 
RUN apt-get install bcc-tools -y
RUN apt-get install libbcc-examples -y
RUN apt-get install -y vim
ENV PYTHONPATH=/usr/lib/python2.7/dist-packages/

COPY requirements.txt /crawler/requirements.txt
RUN pip install -r requirements.txt

ADD crawler /crawler

COPY dependencies/python-socket-datacollector_0.1.1-1_all.deb /tmp
RUN dpkg -i /tmp/python-socket-datacollector_*_all.deb && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install fprobe

ENTRYPOINT [ "python2.7", "crawler.py" ]
