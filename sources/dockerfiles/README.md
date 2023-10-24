This directory contains the dockerfiles used by the CI/CD pipeline, which builds images in two steps
1. Base image, built on top of a `debian:12-slim`
2. Final image, built on top of the base image

Building an image manually can be done in two ways
1. Either build the base and then build the final by giving the BASE_IMAGE_REPO and BASE_IMAGE_NAME arguments
2. Or build the image in one-step by using the dockerfiles in the root directory

Nota bene: the wrapper will look for dockerfiles in the root directory.