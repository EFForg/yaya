FROM golang:1.14.3-alpine AS build

RUN apk add git
RUN apk add pkgconfig
RUN apk add gcc
RUN apk add make
RUN apk add g++
RUN apk add libstdc++
RUN apk add libsigc++
RUN apk add libtool
RUN apk add automake
RUN apk add autoconf
RUN apk add libressl-dev
RUN apk add jansson
RUN apk add jansson-dev
RUN apk add libmagic


WORKDIR /src

RUN wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.0.0.tar.gz && mkdir yara && cd yara && tar xf ../v4.0.0.tar.gz \
    && cd yara-4.0.0/ && ./bootstrap.sh && ./configure --enable-cuckoo --enable-dotnet && make && make install

COPY . .

RUN go get github.com/EFForg/yaya && cd $GOPATH/src/github.com/EFForg/yaya && go build && go install 

RUN mkdir /out/

RUN yaya update && yaya export /out/yaya.rules

FROM scratch AS bin

COPY --from=build /out/yaya.rules ./