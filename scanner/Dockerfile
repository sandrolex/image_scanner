FROM ubuntu:20.04
ENV DEBIAN_FRONTEND noninteractive
run apt-get update -y && \
	apt-get install -y python3 python3-pip wget wget apt-transport-https gnupg lsb-release

RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
RUN echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list
RUN apt-get update
RUN apt-get install -y trivy

WORKDIR /opt

COPY requirements.txt . 
RUN pip3 install -r requirements.txt
COPY app .  

EXPOSE 5010
CMD ["python3", "api2.py"]

