FROM docker.io/golang:alpine as build

WORKDIR /src/containerboot

COPY go.* .

RUN go mod download

COPY . .

RUN go build -o containerboot ./cmd/containerboot

FROM docker.io/alpine:latest

RUN echo "root:root" | chpasswd

RUN apk add --no-cache openssh ca-certificates wget curl

RUN ssh-keygen -A && echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

COPY --from=build /src/containerboot/containerboot /containerboot

EXPOSE 22
EXPOSE 2023

ENTRYPOINT ["/containerboot"]
