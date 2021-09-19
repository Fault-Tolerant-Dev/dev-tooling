########################
## Globals
########################
DOCKER_IMAGE_REPOSITORY :=
PYTHON_BUILD_FROM := builder:alpine3.14.2
GOLANG_BUILD_FROM :=
RUBY_BUILD_FROM :=
GOOGLE_CLOUD_BUILD_FROM :=


##############################
## All - Guess what this does
##############################
.PHONY: all
all: build-bats build-google-cloud build-hadolint build-hashicorp build-kubectl build-shellcheck build-terraform-docs

########################
##
########################
BATS_VERSION := 0.4.0
BATS_SUPPORT_VERSION := 0.3.0
BATS_ASSERT_VERSION := 2.0.0
BATS_MOCK_VERSION := 1.0.1
BATS_BUILD_NAME := bats
BATS_BUILD_TAG := 0.4.0alpine3.14.2

.PHONY: build-bats
build-bats:
	docker build --no-cache \
		--build-arg IMAGE=${BUILD_FROM} \
		--build-arg BATS_VERSION=${BATS_VERSION} \
		--build-arg BATS_SUPPORT_VERSION=${BATS_SUPPORT_VERSION} \
		--build-arg BATS_ASSERT_VERSION=${BATS_ASSERT_VERSION} \
		--build-arg BATS_MOCK_VERSION=${BATS_MOCK_VERSION} \
		-t ${BATS_BUILD_NAME}:${BATS_BUILD_TAG} \
		-f bats/Dockerfile .


python:3.9.7alpine3.14.2
golang:1.16.7alpine3.14.2
ruby:2.6.3alpine3.14.2
python:3.9.7alpine3.14.2
golang:1.16.7alpine3.14.2
golang:1.16.7alpine3.14.2
googlecloud:353.0.0alpine3.14.2
terraform-docs:0.15.0alpine3.14.2
shellcheck:0.6.0alpine3.14.2
hashicorp:0.2.0alpine3.14.2
hadolint:1.15.0alpine3.14.2
bats:0.4.0alpine3.14.2
base:alpine3.14.2