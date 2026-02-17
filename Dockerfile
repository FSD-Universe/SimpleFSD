FROM golang:1.24.0-alpine AS builder

WORKDIR /build

ENV GO111MODULE=on
ENV CGO_ENABLED=1
ENV BUILD_OPUS=1

RUN apk update
RUN apk --no-cache add gcc musl-dev git opus-dev

RUN pkg-config --modversion opus

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go run build.go -docker

FROM alpine:latest AS runtime

RUN apk update
RUN apk --no-cache add ca-certificates curl opus

WORKDIR /service

COPY --from=builder /build/fsd .

RUN mkdir -p /service/data
RUN mkdir -p /service/template

COPY ./template /service/template
COPY ./data /service/data

ENTRYPOINT ["./fsd"]