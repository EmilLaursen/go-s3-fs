package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/pkg/errors"
)

func main() {
	key := os.Getenv("SPACES_KEY")
	secret := os.Getenv("SPACES_SECRET")
	bucketName := os.Getenv("BUCKET_NAME")
	region := "us-east-1"
	endpoint := os.Getenv("ENDPOINT")

	s3Config := &aws.Config{
		Credentials: credentials.NewStaticCredentials(key, secret, ""),
		Endpoint:    aws.String(endpoint),
		Region:      aws.String(region),
	}

	newSession, err := session.NewSession(s3Config)
	if err != nil {
		log.Fatal(err)
	}

	s3Client := s3.New(newSession)

	s3fs := S3FileServer{
		BucketName: bucketName,
		S3Client:   s3Client,
	}
	r := s3fs.GetRouter()
	log.Fatal(http.ListenAndServe(":8080", r))
}

var htmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	// "&#34;" is shorter than "&quot;".
	// "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
	"'", "&#39;",
)

func basicAuthFailed(w http.ResponseWriter, realm string) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	w.WriteHeader(http.StatusUnauthorized)
}

type S3File struct {
	BucketName    string
	Key           string
	S3Client      *s3.S3
	ContentLength int64
	ContentType   string
	LastModified  time.Time
	IsDir         bool
}

func StripSlashes(str string) string {
	return strings.TrimPrefix(strings.TrimPrefix(str, "/"), "/")
}

var ErrS3KeyNotFound = errors.New("Key not found")

type S3FileServer struct {
	BucketName string
	S3Client   *s3.S3
}

func (sfs *S3FileServer) GetRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.BasicAuth("*.pypi.eol.dk", map[string]string{
		"eol": "secret",
	}))
	r.Get("/*", sfs.S3Handler)
	r.Post("/*", sfs.UploadHandler)
	return r
}

func (sfs *S3FileServer) UploadHandler(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	log.Printf("urlPath: %v", urlPath)
	defer r.Body.Close()

	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("read error: %v", err)
	}

	log.Printf("Headers: %+v", r.Header)

	log.Printf("Request: %+v", r)
	log.Printf("recieved bytes: %v", len(bytes))
	log.Printf("recieved bytes: %v", string(bytes))
}

func (sfs *S3FileServer) S3Handler(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	log.Printf("urlPath: %v", urlPath)

	urlPath = StripSlashes(urlPath)
	log.Printf("stripped urlPath: %v", urlPath)

	isRoot := len(urlPath) <= 0
	if isRoot {
		log.Printf("isRoot: %v", isRoot)
		sfs.ServeDirList(w, r, &S3File{
			BucketName:    sfs.BucketName,
			Key:           "",
			S3Client:      sfs.S3Client,
			ContentLength: 0,
			ContentType:   "application/json",
			LastModified:  time.Now(),
			IsDir:         true,
		})
		return
	}

	isIndexHtml := strings.HasSuffix(urlPath, "index.html")
	if isIndexHtml {
		log.Printf("isIndexHtml: %v", urlPath)
		urlPath = strings.TrimSuffix(urlPath, "index.html")
		urlPath = StripSlashes(urlPath)
	}

	s3file, err := sfs.LookupObjectKey(urlPath)
	if err != nil {
		log.Printf("error: %v", err)
		if err == ErrS3KeyNotFound {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("404 Not Found"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 Not Found"))
		return
	}

	log.Printf("s3file: %+v", s3file)

	if s3file.IsDir {
		sfs.ServeDirList(w, r, s3file)
		return
	}

	sfs.ServeFile(w, r, s3file)
}

func (sfs *S3FileServer) LookupObjectKey(key string) (*S3File, error) {
	log.Printf("Calling headobject: %v", key)
	objectInfo, err := sfs.S3Client.HeadObject(
		&s3.HeadObjectInput{
			Bucket: aws.String(sfs.BucketName),
			Key:    aws.String(key),
		},
	)
	log.Printf("Called headobject: %+v, %v", objectInfo, err)
	if err != nil {
		log.Printf("error: %+v", err)
		if awsErr, ok := err.(awserr.Error); ok {
			switch errCode := awsErr.Code(); errCode {
			case "NotFound":
				// Could be a 'directory lookup' lacking trailing slash
				// HeadObject does not handle these
				if !strings.HasSuffix(key, "/") {
					return sfs.LookupObjectKey(key + "/")
				}
				return nil, errors.Wrap(awsErr, "Unexpected HeadObject awserr")
			default:
				log.Printf("default: %v", awsErr.Code())
				return nil, errors.Wrap(awsErr, "Unexpected HeadObject awserr")
			}
		}
		return nil, errors.Wrap(err, "Unexpected HeadObject error")
	}

	contentLength := int64(0)
	if objectInfo.ContentLength != nil {
		contentLength = *objectInfo.ContentLength
	}

	contentType := ""
	if objectInfo.ContentType != nil {
		contentType = *objectInfo.ContentType
	}

	lastModified := time.Now()
	if objectInfo.LastModified != nil {
		lastModified = *objectInfo.LastModified
	}

	return &S3File{
		BucketName:    sfs.BucketName,
		Key:           key,
		S3Client:      sfs.S3Client,
		ContentLength: contentLength,
		ContentType:   contentType,
		LastModified:  lastModified,
		IsDir:         contentLength == 0,
	}, nil
}

func (sfs *S3FileServer) ServeDirList(w http.ResponseWriter, r *http.Request, s3f *S3File) {
	spaces, err := sfs.S3Client.ListObjectsV2(
		&s3.ListObjectsV2Input{
			Bucket: aws.String(s3f.BucketName),
			Prefix: aws.String(s3f.Key),
		},
	)
	if err != nil {
		return
	}

	contents := spaces.Contents
	sort.Slice(contents, func(i, j int) bool { return *contents[i].Key < *contents[j].Key })
	log.Printf("%+v", spaces)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<pre>\n")

	isRoot := strings.EqualFold(StripSlashes(s3f.Key), "")
	if !isRoot {
		url := url.URL{Path: "../"}
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", url.String(), "..")
	}
	for _, filekey := range contents {
		key := *filekey.Key

		// Since S3 has no concept of folder structure, listing obvjects at a prefix
		// will list every object in every "subfolder".
		//
		// To simulate regular filesystems, we ignore these keys
		log.Printf("readdir key: %v", key)
		key = strings.TrimPrefix(key, s3f.Key)
		log.Printf("trimmed key: %v", key)

		split := strings.Split(strings.TrimPrefix(key, "/"), "/")
		count := 0
		for _, subkey := range split {
			if len(subkey) > 0 {
				count += 1
			}
		}

		log.Printf("Split: %v, non trivial splits: %v", split, count)
		isInSubfolder := count != 1
		if isInSubfolder {
			log.Printf("is in subfolder: %v", *filekey.Key)
			continue
		}

		url := url.URL{Path: key}
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", url.String(), htmlReplacer.Replace(key))
	}
	fmt.Fprintf(w, "</pre>\n")
}

func (sfs *S3FileServer) ServeFile(w http.ResponseWriter, r *http.Request, s3f *S3File) {
	log.Printf("Downloading file %v", s3f.Key)

	objOutput, err := sfs.S3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s3f.BucketName),
		Key:    aws.String(s3f.Key),
	})
	if err != nil {
		log.Printf("GetObject error %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer objOutput.Body.Close()

	w.Header().Add("Content-Type", s3f.ContentType)
	w.Header().Add("Content-Length", strconv.FormatInt(s3f.ContentLength, 10))
	w.Header().Add("Last-Modified", s3f.LastModified.String())

	written, err := io.Copy(w, objOutput.Body)
	if err != nil {
		log.Printf("Copy s3 object error %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("Written %v bytes", written)
}
