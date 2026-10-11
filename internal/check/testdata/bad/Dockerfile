FROM ubuntu:latest
ENV API_KEY=supersecret123
RUN curl https://example.com/install.sh | sh
ADD https://example.com/file.tar.gz /tmp/
COPY . /app
RUN sudo apt-get update
CMD ["/app/run"]
