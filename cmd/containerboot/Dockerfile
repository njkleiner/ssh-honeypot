FROM docker.io/library/golang@sha256:ace6cc3fe58d0c7b12303c57afe6d6724851152df55e08057b43990b927ad5e8 as build

WORKDIR /src/containerboot

COPY go.* .

RUN go mod download

COPY . .

RUN go build -o containerboot ./cmd/containerboot

FROM docker.io/library/alpine@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0

RUN apk add --no-cache openssh ca-certificates wget curl
RUN echo "root:root" | chpasswd && ssh-keygen -A && echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

COPY --from=build /src/containerboot/containerboot /containerboot

EXPOSE 22
EXPOSE 2023

ENTRYPOINT ["/containerboot"]
