# Step 1
FROM python:3.9.7alpine3.14.2 as python
WORKDIR /build
ADD ./data/requirements.txt .
RUN pip3 install -r requirements.txt

FROM golang:1.16.7alpine3.14.2 as golang

FROM ruby:2.6.3alpine3.14.2 as ruby
WORKDIR /build
ADD ./data/Gemfile* .
RUN apk add --no-cache build-base
RUN gem install bundler -v 1.17.3 && bundle install

# Step 2
FROM python:3.9.7alpine3.14.2 as boilerplate
WORKDIR /build
ADD ./verify_boilerplate .
RUN install -o 0 -g 0 -m 0755 -d /usr/local/verify_boilerplate && \
    install -o 0 -g 0 -m 0755 verify_boilerplate.py /usr/local/verify_boilerplate/verify_boilerplate.py && \
    install -o 0 -g 0 -m 0644 boilerplate/*.txt -D -t /usr/local/verify_boilerplate/boilerplate/

FROM golang:1.16.7alpine3.14.2 as module-swapper
WORKDIR /build
ADD ./scripts/module-swapper .
RUN go build -v -o /usr/local/bin/module-swapper

FROM golang:1.16.7alpine3.14.2 as addlicense
WORKDIR /build
RUN go get -u github.com/google/addlicense@v1.0.0
RUN cp /go/bin/addlicense /usr/local/bin/

FROM googlecloud:353.0.0alpine3.14.2 as google-cloud
WORKDIR /build
ADD ./data/components.txt .
RUN xargs -a components.txt gcloud components install --quiet
RUN rm -rf /google-cloud-sdk/.install/.backup/* && \
    rm -f /google-cloud-sdk/bin/kubectl.1.*

# Step 3
FROM terraform-docs:0.15.0alpine3.14.2 as terraform-docs
FROM shellcheck:0.6.0alpine3.14.2 as shellcheck
FROM hashicorp:0.2.0alpine3.14.2  as hashicorp
FROM hadolint:1.15.0alpine3.14.2 as hadolint
FROM bats:0.4.0alpine3.14.2 as bats
FROM kics:1.4.5alpine3.14.2 as kics

# Step 3
FROM base:alpine3.14.2
ENV WORKSPACE="/workspace"
ENV PATH /usr/local/go/bin:/usr/local/bundle/bin:/usr/local/google-cloud-sdk/bin:$PATH
ENV GEM_HOME /usr/local/bundle

ARG KITCHEN_TEST_BASE_PATH="test/integration"
ENV KITCHEN_TEST_BASE_PATH ${KITCHEN_TEST_BASE_PATH}

ARG TF_PLUGIN_CACHE_DIR="/workspace/test/integration/tmp/.terraform"
ENV TF_PLUGIN_CACHE_DIR ${TF_PLUGIN_CACHE_DIR}
RUN mkdir -p ${TF_PLUGIN_CACHE_DIR}

COPY --from=python /usr /usr
COPY --from=golang /usr/local /usr/local
COPY --from=ruby /usr /usr

COPY --from=boilerplate /usr/local/verify_boilerplate /usr/local/verify_boilerplate
COPY --from=module-swapper /usr/local/bin/module-swapper /usr/local/bin/module-swapper
COPY --from=add-license /usr/local/bin/addlicense /usr/local/bin/addlicense
COPY --from=terraform-docs /usr/local/bin/terraform-docs /usr/local/bin/terraform-docs
COPY --from=shellcheck /usr/local/bin/shellcheck /usr/local/bin/shellcheck
COPY --from=hashicorp /software/terraform0.13.7 /usr/local/bin/terraform
COPY --from=hadolint /usr/local/bin/hadolint /usr/local/bin/hadolint
COPY --from=google-cloud /root/.config /root/.config
COPY --from=google-cloud /google-cloud-sdk /usr/local/google-cloud-sdk
COPY --from=bats /usr/local /usr/local
COPY --from=kics /usr/local/kics /usr/local/kics

RUN apk add --no-cache coreutils curl findutils git ca-certificates diffutils rsync gettext libintl bash parallel gmp-dev libc6-compat

ADD ./scripts/task_wrapper_scripts/* /usr/local/bin/
ADD ./scripts/*.py /usr/local/bin/
ADD ./scripts/*.sh /usr/local/bin/

ADD ./home/bash_history /root/.bash_history
ADD ./home/bashrc /root/.bashrc

WORKDIR $WORKSPACE
RUN python --version && \
    go version && \
    ruby --version && \
    bundle --version && \
    kitchen version && \
    terraform-docs --version && \
    shellcheck --version && \
    terraform --version && \
    hadolint --version && \
    gcloud --version && \
    gsutil --version && \
    kubectl version --client=true && \
    kpt version && \
    kustomize version && \
    bats --version

CMD ["/bin/bash"]




