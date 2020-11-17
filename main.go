package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/EmilLaursen/go-s3-fs/libraries/box"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	// _ "net/http/pprof"

	"github.com/ante-dk/envconfig"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/gabriel-vasile/mimetype"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/pkg/errors"
)

type Config struct {
	Key        string `envconfig:"SPACES_KEY" required:"true"`
	Secret     string `envconfig:"SPACES_SECRET" required:"true"`
	BucketName string `envconfig:"BUCKET_NAME" required:"true"`
	BasePath   string `envconfig:"BASE_PATH" default:"/"`
	Endpoint   string
	Region     string
	Port       string `default:"8080"`
}

const Kb int = 1024
const Mb int = Kb * Kb

func main() {
	var c Config
	err := envconfig.Process("", &c)
	if err != nil {
		log.Fatal().Err(err)
	}

	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Printf("%+v", c)

	// Check box for TLS certs
	TLSCert, certOK := box.Get("/cert.pem")
	TLSKey, keyOK := box.Get("/key.pem")
	ClientCACert, cCertOk := box.Get("/client-ca.pem")

	// Setup S3 client session
	newSession, err := session.NewSession(
		&aws.Config{
			Credentials: credentials.NewStaticCredentials(c.Key, c.Secret, ""),
			Endpoint:    aws.String(c.Endpoint),
			Region:      aws.String(c.Region),
		})

	if err != nil {
		log.Fatal().Err(err)
	}

	s3fs := NewS3FileServer(c.BucketName, c.BasePath, s3.New(newSession))

	r := s3fs.GetRouter()

	baseRouter := chi.NewRouter()

	baseRouter.Use(middleware.RequestID)
	baseRouter.Use(middleware.RealIP)
	baseRouter.Use(middleware.Recoverer)
	baseRouter.Use(middleware.Timeout(60 * time.Second))

	baseRouter.Mount(c.BasePath, r)

	faviconRouter := chi.NewRouter()
	faviconRouter.Get("/favicon.ico", FaviconHandler)
	baseRouter.Mount("/", faviconRouter)

	var tlsConfig *tls.Config
	useTLS := certOK && keyOK && cCertOk
	if useTLS {
		tlsConfig, err = GetTLSConfig(ClientCACert, TLSCert, TLSKey)
		if err != nil {
			log.Fatal().Err(err).Msg("TLS config failed")
		}

	} else {
		tlsConfig = nil
	}

	server := &http.Server{
		Addr:      ":" + c.Port,
		Handler:   baseRouter,
		TLSConfig: tlsConfig,
	}

	if useTLS {
		log.Info().Msg("Using TLS")
		log.Fatal().Err(server.ListenAndServeTLS("", ""))
		return
	}
	log.Fatal().Err(server.ListenAndServe())

}

var htmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	"'", "&#39;",
)

type S3File struct {
	BucketName    string
	Key           string
	ContentLength int64
	ContentType   string
	LastModified  time.Time
	IsDir         bool
}

type S3FileServer struct {
	BucketName   string
	S3Client     *s3.S3
	S3Downloader *s3manager.Downloader
	S3Uploader   *s3manager.Uploader
	BasePath     string
}

func NewS3FileServer(BucketName, BasePath string, S3Client *s3.S3) S3FileServer {

	s3Downloader := s3manager.NewDownloaderWithClient(S3Client, func(d *s3manager.Downloader) {
		d.BufferProvider = s3manager.NewPooledBufferedWriterReadFromProvider(256 * Kb)
		d.Concurrency = 1
		d.PartSize = int64(64 * Mb)
	})

	s3Uploader := s3manager.NewUploaderWithClient(S3Client)

	return S3FileServer{
		BucketName:   BucketName,
		S3Client:     S3Client,
		S3Downloader: s3Downloader,
		S3Uploader:   s3Uploader,
		BasePath:     BasePath,
	}
}

func (sfs *S3FileServer) GetRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r.Get("/*", sfs.S3Handler)
	r.Post("/*", sfs.StreamUploadHandler)
	return r
}

func (sfs *S3FileServer) StreamUploadHandler(w http.ResponseWriter, r *http.Request) {

	mReader, err := r.MultipartReader()
	if err != nil {
		log.Printf("failed to create stream reader for multipart form: %+v", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// The fields we extract
	metadataFields := NewStringSet("name", "md5_digest")
	fileFields := NewStringSet("content")

	metadata := make(map[string]string, metadataFields.Length())
	var file *multipart.Part

	nextPart, err := mReader.NextPart()
	log.Printf("nextpart: %v, error: %v", nextPart, err)

	for i := 0; err == nil && i < 50; i++ {
		fname := nextPart.FormName()

		if metadataFields.Contains(fname) {

			bytes, readErr := ioutil.ReadAll(nextPart)
			if readErr != nil {
				log.Printf("failed to read next part bytes: %+v", err)
				continue
			}

			metadata[nextPart.FormName()] = string(bytes)

		} else if fileFields.Contains(nextPart.FormName()) {

			file = nextPart
			// must break otherwise the bytes are read, and the file is lost
			break

		} else {
			nextPart.Close()
		}

		nextPart, err = mReader.NextPart()

	}

	base64Md5Digest, err := ConvertHexToBase64(metadata["md5_digest"])
	if err != nil {
		log.Printf("encode to base64 failed: %+v", err)
		http.Error(w, "", http.StatusBadRequest)
	}

	// log.Printf("values: %+v", metadata)
	// log.Printf("file: %v", file)

	packageName := metadata["name"]
	s3Destination := filepath.Join(packageName, file.FileName())

	// peek mimetype from reader, and rebuild it
	var mimetypeDetectionBytes bytes.Buffer
	tReader := io.TeeReader(file, &mimetypeDetectionBytes)

	contentType, err := mimetype.DetectReader(tReader)
	if err != nil {
		log.Printf("mimetype.DetectReader error: %+v", err)
		http.Error(w, "", http.StatusBadRequest)
	}

	body := io.MultiReader(&mimetypeDetectionBytes, file)

	log.Printf("S3Destination: %v", s3Destination)
	log.Printf("contentType: %v", contentType.String())
	log.Printf("md5Digest: %v", base64Md5Digest)

	uploadOutput, err := sfs.S3Uploader.UploadWithContext(r.Context(), &s3manager.UploadInput{
		Bucket:             aws.String(sfs.BucketName),
		Key:                aws.String(s3Destination),
		Body:               body,
		ContentMD5:         aws.String(base64Md5Digest),
		ContentDisposition: aws.String(fmt.Sprintf(`attachment; filename="%s"`, file.FileName())),
		// ContentLength:      aws.Int64(fileSize),
		ContentType: aws.String(contentType.String()),
	})
	if err != nil {
		log.Printf("UploadWithContext error: %+v", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	log.Printf("uploaded %v to: %v", file.FileName(), uploadOutput.Location)

}

func (sfs *S3FileServer) S3Handler(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	log.Printf("called urlPath: %v", urlPath)
	urlPath = strings.TrimPrefix(urlPath, sfs.BasePath)

	if len(urlPath) <= 0 {
		// Redirect host:port/BasePath to host:port/BasePath/
		http.Redirect(w, r, r.URL.Path+"/", http.StatusSeeOther)
		return
	}

	urlPath = strings.TrimPrefix(urlPath, "/")

	isRoot := len(urlPath) <= 0
	if isRoot {
		sfs.ServeDirList(w, r, "")
		return
	}

	isIndexHtml := strings.HasSuffix(urlPath, "index.html")
	if isIndexHtml {
		log.Printf("isIndexHtml: %v", urlPath)
		urlPath = strings.TrimSuffix(urlPath, "index.html")
		urlPath = StripSlashes(urlPath)
	}

	if isDir := strings.HasSuffix(urlPath, "/"); isDir {
		sfs.ServeDirList(w, r, urlPath)
		return
	}

	s3file, err := sfs.LookupObjectKey(r.Context(), urlPath)
	if err != nil {
		log.Printf("error: %v", err)
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	if s3file.IsDir {
		// Folder was requested without trailing "/". We should redirect to path + "/"
		http.Redirect(w, r, strings.TrimSuffix(urlPath, "/")+"/", http.StatusSeeOther)
		return
	}

	sfs.ServeFile(w, r, s3file)
}

func (sfs *S3FileServer) LookupObjectKey(ctx context.Context, key string) (*S3File, error) {
	log.Printf("Calling headobject: %v", key)
	objectInfo, err := sfs.S3Client.HeadObjectWithContext(
		ctx,
		&s3.HeadObjectInput{
			Bucket: aws.String(sfs.BucketName),
			Key:    aws.String(key),
		},
	)

	if err != nil {
		log.Printf("error: %+v", err)
		if awsErr, ok := err.(awserr.Error); ok {
			switch errCode := awsErr.Code(); errCode {
			case "NotFound":
				// Could be a 'directory lookup' lacking trailing slash
				// HeadObject does not handle these
				spaces, err := sfs.S3Client.ListObjectsV2WithContext(
					ctx,
					&s3.ListObjectsV2Input{
						Bucket: aws.String(sfs.BucketName),
						Prefix: aws.String(strings.TrimSuffix(key, "/") + "/"),
					},
				)
				if err != nil {
					log.Printf("LookupObjectKey, ListObjectsV2 error: %v", awsErr.Code())
				}

				log.Printf("LookupObjectKey, ListObjectsV2(%v, %v): %+v", sfs.BucketName, key, spaces)
				if len(spaces.Contents) > 0 {
					return &S3File{
						BucketName:    sfs.BucketName,
						Key:           key,
						ContentLength: 0,
						ContentType:   "application/json",
						LastModified:  time.Now(),
						IsDir:         true,
					}, nil
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
		ContentLength: contentLength,
		ContentType:   contentType,
		LastModified:  lastModified,
		IsDir:         contentLength == 0,
	}, nil
}

func (sfs *S3FileServer) ServeDirList(w http.ResponseWriter, r *http.Request, objectKey string) {
	spaces, err := sfs.S3Client.ListObjectsV2WithContext(
		r.Context(),
		&s3.ListObjectsV2Input{
			Bucket: aws.String(sfs.BucketName),
			Prefix: aws.String(objectKey),
		},
	)
	if err != nil || len(spaces.Contents) <= 0 {
		log.Printf("ListObjectsV2 error: %+v", err)
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	// Prepare the index.html response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<pre>\n")

	if isRoot := strings.EqualFold(StripSlashes(objectKey), ""); !isRoot {
		url := url.URL{Path: "../"}
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", url.String(), "..")
	}

	// ListObjects with a prefix, will list all objects with that prefix. To simulate a directory
	// structure, we parse the returned objects for content in the current 'folder', and content in
	// subfolders
	// Some S3 managers will simulate folders by creating empty files with objectKeys ending in "/"
	// This happens if you create a folder in the Digital Ocean GUI, or the AWS S3 gui.

	// Simple set implementation
	subFoldersSeen := NewStringSet()

	// make(map[string]bool)
	folderContent := make([]string, 0)
	for _, filekey := range spaces.Contents {
		key := *filekey.Key

		// In case the 'folder' exists on S3, we make sure it ignore it.
		key = strings.TrimPrefix(key, objectKey)
		if len(key) <= 0 {
			continue
		}

		split := strings.Split(strings.TrimPrefix(key, "/"), "/")

		if len(split) >= 2 {
			// folder (key=folder_name/) split to ['folder_name', ''] -> count == 1
			// files in current folder split to ['file_name'] --> count == 1
			// stuff in subfolders get count > 1 (and root folder get count 0)
			subFolder := split[0]
			if !subFoldersSeen.Contains(subFolder) {
				folderContent = append(folderContent, subFolder+"/")
				subFoldersSeen.Add(subFolder)
			}
		}

		if len(split) == 1 {
			file := split[0]
			folderContent = append(folderContent, file)
		}

		if len(split) == 0 {
			log.Printf("!!!! WTF !! SPLIT HAS LENGTH 0: %v", key)
		}
	}

	// make sure directories go on top
	sort.SliceStable(folderContent, func(i, j int) bool {
		fst := folderContent[i]
		snd := folderContent[j]
		if strings.HasSuffix(fst, "/") {
			if strings.HasSuffix(snd, "/") {
				return fst < snd
			}
			return true
		}

		if strings.HasSuffix(snd, "/") {
			return false
		}

		return fst < snd
	})

	for _, key := range folderContent {
		url := url.URL{Path: key}
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", url.String(), htmlReplacer.Replace(key))
	}
	fmt.Fprintf(w, "</pre>\n")
}

type FakeWriterAt struct {
	w io.Writer
}

func (fw FakeWriterAt) WriteAt(p []byte, offset int64) (n int, err error) {
	// ignore 'offset' because we forced sequential downloads, with downloader.Concurrency = 1
	return fw.w.Write(p)
}

func (sfs *S3FileServer) ServeFile(w http.ResponseWriter, r *http.Request, s3f *S3File) {
	log.Printf("Serving file %v", s3f.Key)
	defer r.Body.Close()

	w.Header().Add("Content-Type", s3f.ContentType)
	w.Header().Add("Content-Length", strconv.FormatInt(s3f.ContentLength, 10))
	w.Header().Add("Last-Modified", s3f.LastModified.String())

	log.Printf("Content-type: %v", s3f.ContentType)
	log.Printf("Content-Length: %v", strconv.FormatInt(s3f.ContentLength, 10))
	log.Printf("Last-Modified: %v", s3f.LastModified.String())

	_, err := sfs.S3Downloader.DownloadWithContext(r.Context(), FakeWriterAt{w}, &s3.GetObjectInput{
		Bucket: aws.String(s3f.BucketName),
		Key:    aws.String(s3f.Key),
	})
	if ctxErr := r.Context().Err(); ctxErr != nil {
		log.Printf("DownloadWithContext, context cancelled error %v", ctxErr)
		return
	}

	if err != nil {
		log.Printf("DownloadWithContext error %v", err)

		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	// objOutput, err := sfs.S3Client.GetObjectWithContext(r.Context(), &s3.GetObjectInput{
	// 	Bucket: aws.String(s3f.BucketName),
	// 	Key:    aws.String(s3f.Key),
	// })
	// if err != nil {
	// 	log.Printf("GetObject error %v", err)
	// 	http.Error(w, "404 Not Found", http.StatusNotFound)
	// 	return
	// }
	// defer objOutput.Body.Close()

	// memoryBuffer := make([]byte, 256*Kb)
	// if _, err = CopyBufferWithContext(r.Context(), w, objOutput.Body, memoryBuffer); err != nil {
	// 	log.Printf("Copy s3 object error %v", err)
	// 	http.Error(w, "404 Not Found", http.StatusNotFound)
	// 	return
	// }

}

func FaviconHandler(w http.ResponseWriter, r *http.Request) {
	favicon, ok := box.Get("/favicon.ico")
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	if _, err := CopyBufferWithContext(r.Context(), w, bytes.NewReader(favicon), nil); err != nil {
		log.Printf("Copy favicon error %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type StringSet struct {
	set map[string]struct{}
}

func NewStringSet(elems ...string) StringSet {
	set := StringSet{
		set: make(map[string]struct{}),
	}
	for _, e := range elems {
		set.Add(e)
	}
	return set
}

func (s *StringSet) Length() int {
	return len(s.set)
}

func (s *StringSet) Add(e string) {
	s.set[e] = struct{}{}
}

func (s *StringSet) Contains(e string) bool {
	_, ok := s.set[e]
	return ok
}

func (s *StringSet) Delete(e string) {
	delete(s.set, e)
}

func StripSlashes(str string) string {
	return strings.TrimPrefix(strings.TrimSuffix(str, "/"), "/")
}

func ConvertHexToBase64(hexEncoded string) (string, error) {
	bytes, err := hex.DecodeString(hexEncoded)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func GetTLSConfig(caCert []byte, TLSCert []byte, TLSKey []byte) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	certificate, err := tls.X509KeyPair(TLSCert, TLSKey)
	if err != nil {
		return nil, err
	}

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

// here is some syntaxic sugar inspired by the Tomas Senart's video,
// it allows me to inline the Reader interface
type readerFunc func(p []byte) (n int, err error)

func (rf readerFunc) Read(p []byte) (n int, err error) { return rf(p) }

// slightly modified function signature:
// - context has been added in order to propagate cancelation
// - I do not return the number of bytes written, has it is not useful in my use case
func CopyBufferWithContext(ctx context.Context, dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if buf == nil {
		buf = make([]byte, 32*Kb)
	}

	// Copy will call the Reader and Writer interface multiple time, in order
	// to copy by chunk (avoiding loading the whole file in memory).
	// I insert the ability to cancel before read time as it is the earliest
	// possible in the call process.
	return io.CopyBuffer(dst, readerFunc(func(p []byte) (int, error) {

		// golang non-blocking channel: https://gobyexample.com/non-blocking-channel-operations
		select {

		// if context has been canceled
		case <-ctx.Done():
			// stop process and propagate "context canceled" error
			return 0, ctx.Err()
		default:
			// otherwise just run default io.Reader implementation
			return src.Read(p)
		}
	}), buf)
}
