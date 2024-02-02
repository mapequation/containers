# containers

Dockerfiles for useful containers

## Build

Using `jupyter-scipy` as an example:

```sh
cd jupyter-scipy
docker build --tag 'my-jupyter-scipy' .
```

## Run

For jupyter, see https://jupyter-docker-stacks.readthedocs.io/en/latest/using/running.html, for example:

```sh
docker run -it --rm -p 8888:8888 -v "${PWD}":/home/jovyan/work my-jupyter-scipy
```
