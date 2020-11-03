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
	// go func() {
	// 	log.Fatal().Err(http.ListenAndServe(":6060", nil))
	// }()

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

	s3Client := s3.New(newSession)

	s3Downloader := s3manager.NewDownloaderWithClient(s3Client, func(d *s3manager.Downloader) {
		d.BufferProvider = s3manager.NewPooledBufferedWriterReadFromProvider(256 * Kb)
		d.Concurrency = 1
		d.PartSize = int64(64 * Mb)
	})

	s3fs := S3FileServer{
		BucketName:   c.BucketName,
		S3Client:     s3Client,
		S3Downloader: s3Downloader,
		BasePath:     c.BasePath,
	}

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
	// "&#34;" is shorter than "&quot;".
	// "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
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
	BasePath     string
}

func (sfs *S3FileServer) GetRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r.Get("/*", sfs.S3Handler)
	r.Post("/*", sfs.UploadHandler)
	return r
}

func (sfs *S3FileServer) UploadHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	urlPath := r.URL.Path
	log.Printf("urlPath: %v", urlPath)

	// 32mb in memory, rest on disk
	parseErr := r.ParseMultipartForm(32 << 20)
	if parseErr != nil {
		log.Printf("failed to parse multipart form: %+v", parseErr)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	packageName := r.FormValue("name")
	log.Debug().Msgf("Multipart-form name: %v", packageName)

	if len(packageName) <= 0 {
		log.Printf("Illegal multipart format. No name supplied.")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	f, fh, err := r.FormFile("content")
	if err != nil {
		log.Printf("FormFile content error: %+v", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	defer f.Close()
	s3Destination := filepath.Join(packageName, fh.Filename)
	contentType, err := mimetype.DetectReader(f)
	if err != nil {
		log.Printf("mimetype.DetectReader error: %+v", err)
		http.Error(w, "", http.StatusBadRequest)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		log.Printf("f.Seek(0, io.SeekStart) error: %+v", err)
		http.Error(w, "", http.StatusBadRequest)
	}

	base64Md5Digest, err := ConvertHexToBase64(r.FormValue("md5_digest"))
	if err != nil {
		log.Printf("encode to base64 failed: %+v", err)
		http.Error(w, "", http.StatusBadRequest)
	}
	size := fh.Size
	log.Printf("S3Destination: %v", s3Destination)
	log.Printf("contentType: %v", contentType.String())
	log.Printf("md5Digest: %v", base64Md5Digest)
	log.Printf("size: %v", size)

	_, err = sfs.S3Client.PutObjectWithContext(
		r.Context(),
		&s3.PutObjectInput{
			Bucket:             aws.String(sfs.BucketName),
			Key:                aws.String(s3Destination),
			Body:               f,
			ContentMD5:         aws.String(base64Md5Digest),
			ContentDisposition: aws.String(fmt.Sprintf(`attachment; filename="%s"`, fh.Filename)),
			ContentLength:      aws.Int64(size),
			ContentType:        aws.String(contentType.String()),
		},
	)
	if err != nil {
		log.Printf("putObject error: %+v", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}
}

func (sfs *S3FileServer) S3Handler(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	log.Printf("urlPath: %v", urlPath)
	urlPath = strings.TrimPrefix(urlPath, sfs.BasePath)
	log.Printf("urlPath trimmed BasePath: %v", urlPath)

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
	subFoldersSeen := make(map[string]bool)
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
			if _, ok := subFoldersSeen[subFolder]; !ok {
				folderContent = append(folderContent, subFolder+"/")
				subFoldersSeen[subFolder] = true
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

	sort.SliceStable(folderContent, func(i, j int) bool { return folderContent[i] < folderContent[j] })

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

	_, err := sfs.S3Downloader.DownloadWithContext(r.Context(), FakeWriterAt{w}, &s3.GetObjectInput{
		Bucket: aws.String(s3f.BucketName),
		Key:    aws.String(s3f.Key),
	})
	ctxErr := r.Context().Err()
	if ctxErr != nil {
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

	// // 32 mega byte ? mibi byte?
	// bufferSize := 32 * 1024
	// buffer := make([]byte, bufferSize)

	// if _, err := io.CopyBuffer(w, objOutput.Body, buffer); err != nil {
	// 	log.Printf("Copy s3 object error %v", err)
	// 	http.Error(w, "404 Not Found", http.StatusNotFound)
	// 	return
	// }
	w.Header().Add("Content-Type", s3f.ContentType)
	w.Header().Add("Content-Length", strconv.FormatInt(s3f.ContentLength, 10))
	w.Header().Add("Last-Modified", s3f.LastModified.String())
}

func FaviconHandler(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("/favicon.ico called !")
	favicon, ok := box.Get("/favicon.ico")
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := io.Copy(w, bytes.NewReader(favicon)); err != nil {
		log.Printf("Copy favicon error %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
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
