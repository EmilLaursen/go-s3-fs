# go-s3-fs

Simple auto-indexed fileserver using S3 as a backend. It is possible to use `mTLS` in the application layer, by adding certificate files before compiling. Additionally, it can be used as a private pypi server, as it will parse package publish requests made by `pip` or `poetry`. 

# Usage

The configurable variables are:
```golang
type Config struct {
	Key        string `envconfig:"SPACES_KEY" required:"true"`
	Secret     string `envconfig:"SPACES_SECRET" required:"true"`
	BucketName string `envconfig:"BUCKET_NAME" required:"true"`
	BasePath   string `envconfig:"BASE_PATH" default:"/"`
	Endpoint   string
	Region     string
	Port       string `default:"8080"`
}
```
To run locally, put these in an `do.env` file, or put them directly in the compose file. Files placed in `/static` will be baked into the compiled binary. If you wish to use `mTLS` in the application layer, you can place files certificate files `client-ca.pem, key.pem, cert.pem` in this folder.

Then launch the server locally with
```bash
docker-compose up -d --build
```

You can create an arm-based image with
```bash
make build-amd64
```
A sample Kubernetes `.yaml` stack is found in `/k8s`.

# Setup private Pypi server

## Publish packages (with poetry)

Add a private repository. See [here](https://python-poetry.org/docs/repositories/#adding-a-repository) for more information:
```bash
poetry config repositories.eol http://localhost:8080
```
To publish a package with poetry to the configured repository
```bash
cd my-python-package
poetry publish --repository eol --build
```
If you use `mTLS` you can supply the client certificate
```bash
poetry config certificates.eol.client-cert /path/to/cert.pem
```
The required format is PEM with both the certificate and private key in a single file.

## Install packages (with pip)

Download packages from official pypi and private repository (with mTLS, with basic auth).
```bash
pip install --trusted-host localhost:8080 --client-cert <path> --extra-index-url http://localhost:8080 -r requirements.txt
```
Note the required format for the client certificate (like above):

## Allow poetry to resolve dependencies for you packages

You propably want to add your published package to some `pyproject.toml` file, but this requires that `poetry` knows about your private repository and has access to it.

To enable this, you add your repository to the `.toml` file like so:
```
[[tool.poetry.source]]
name = "eol"
url = "http://localhost:8080"
```
If you use `mTLS` then poetry also needs to know your client certificates:
```
poetry config certificates.eol.client-cert /path/to/client.pem
```
It is now possible to write
```
poetry add MY-AWSOME-PACKAGE
```
and poetry will perform dependency resolution based on the dependency version ranges in your published package.


# TODO

- [ ] Refactor codebase.
- [ ] minio.io integration in docker-compose setup
- [x] Use some structured logging library
  - [ ] Rework log messages. Use more key/values 
- [ ] Prometheus instrumentation
- [ ] Use golanglint.ci

- [x] Enable uploads from pypi. They send multipart forms to root "/" on a post. Parse and uplaod this to s3.
- [x] Test mTLS/client-cert authentication with pip install and poetry publish
- [x] Dockerfile
  - [x] Embed files into binary (favicon + certificates)
- [x] Docker compose
- [x] Create Kubernetes yaml (w/ istio)
