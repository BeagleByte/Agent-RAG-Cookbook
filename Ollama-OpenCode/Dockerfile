FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
  curl ca-certificates git openssh-client sudo bash jq iputils-ping \
  && rm -rf /var/lib/apt/lists/*

# non-root user
RUN useradd -m -s /bin/bash op \
  && echo "op ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/op \
  && chmod 0440 /etc/sudoers.d/op

USER op
WORKDIR /home/op
ENV HOME=/home/op

# install OpenCode (official installer)
RUN curl -fsSL https://opencode.ai/install | bash

# ensure opencode bin on PATH for non-login shells
ENV PATH=/home/op/.opencode/bin:$PATH

# copy default opencode config (optional)
COPY --chown=op:op opencode/config/config.json /home/op/.config/opencode/config.json

# entrypoint: keep container interactive; default to a shell
ENTRYPOINT ["/bin/bash"]
