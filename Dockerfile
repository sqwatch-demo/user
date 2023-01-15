FROM golang:1.19-alpine
ENV sourcesdir /go/src/github.com/sqwatch-demo/user/
ENV MONGO_HOST mytestdb:27017
ENV HATEAOS user
ENV USER_DATABASE mongodb

COPY . ${sourcesdir}
RUN apk update
RUN apk add git
#RUN go get -v github.com/Masterminds/glide && cd ${sourcesdir} && glide install && go install
RUN go mod vendor

ENTRYPOINT user
EXPOSE 8084
