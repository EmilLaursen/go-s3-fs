# Usage


Fill out `do.env` and 
```bash
set -a && source do.env && set +a
```
Then
```bash
go run ./main.go
```

# Pypi server specifics

## Publish packages to private pypi

Use poetry to add a repository named `eol`. This is necessary for `poetry publish` to work. Use https if available. See [here](https://python-poetry.org/docs/repositories/#adding-a-repository) for more information:
```
poetry config repositories.eol http://localhost:8080
poetry config repositories.eol https://localhost:8080
```
To publish a package with poetry to the configured repository
```
poetry publish --repository eol --build
```
If you use `mTLS` you can supply the client certificate
```
poetry config certificates.eol.client-cert /path/to/cert.pem
```
The required format is PEM with both the certificate and private key in a single file.

## Install packages from private repo (with pip)

Download packages from official pypi and private repository (with mTLS, with basic auth).
```
pip install --client-cert <path> --extra-index-url https://localhost:8080 -r requirements.txt
```
Note the required format for the client certificate (like above):
```
--client-cert <path> Path to SSL client certificate, a single file containing the private key and the certificate in PEM format.
```

## Allow poetry to resolve dependencies for packages in private repo

You propably want to add your published package to some `pyproject.toml` file, but this requires that `poetry` knows about your private repository and has access to it.

To enable this, you add your repository to the `.toml` file like so:
```
[[tool.poetry.source]]
name = "eol"
url = "https://localhost:8080"
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




# S3

S3 has no concept of folders, it is a flat key/value store. The folder structure is simulated by parsing '/' delimiters, or looking at content length etc.

This presents some challanges for the file server, due to the standard way a browser traverses and calls 'directories'.

We use a few rules to determine whether something is a file or directory.

# TODO

- [x] Enable uploads from pypi. They send multipart forms to root "/" on a post. Parse and uplaod this to s3.
- [x] Test mTLS/client-cert authentication with pip install and poetry publish
- [x] Dockerfile
  - [x] Embed files into binary (favicon + certificates)
- [x] Docker compose
- [ ] Create CLI usage gif !
- [ ] Create Kubernetes yaml (istio service)
- [ ] Refactor codebase.
  - [ ] minio.io integration test setup
- [ ] tests
- [x] Use some structured logging library
  - [ ] Remove uncesseary log messages, and convert useful ones to have proper key/values
- [ ] Prometheus instrumentation
- [x] Remove s3client from S3file
- [ ] Use golanglint.ci !
- [ ] Look into using [filepath](https://golang.org/pkg/path/filepath/#Join) for some of the path/objectKey operations
- [x] Poetry publish sends a hex 128 bit md5 hash. If converted to base64, this could perhaps be used as ContentMD5 in putObject to S3. S3 needs digest of the entire response, without headers. So it may not work? See this for [convertion to base64](https://medium.com/@wgallagher86/hex-to-base64-encoding-in-go-ee7fd8e8fd69)
- [ ] Upload of arbitrary files.. Current option is multipart form, with folder name in 'name' field..
- [ ] Parse request url paths using some s3-object key validation regex
- [ ] Use header routing to filter requests. We listen on EVERYTHING. THis is pretty bad. Need various ways to filter shitty requests. This could also be a security issue? Who knows?