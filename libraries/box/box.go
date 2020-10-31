//go:generate go run ../../generate_static/generator.go

package box

type embedBox struct {
	storage map[string][]byte
}

// Create new box for embed files
func newEmbedBox() *embedBox {
	return &embedBox{storage: make(map[string][]byte)}
}

// Add a file to box
func (e *embedBox) Add(file string, content []byte) {
	e.storage[file] = content
}

// Get file's content
// Always use / for looking up
// For example: /init/README.md is actually configs/init/README.md
func (e *embedBox) Get(file string) ([]byte, bool) {
	f, ok := e.storage[file]
	return f, ok
}

// Embed box expose
var box = newEmbedBox()

// Add a file content to box
func Add(file string, content []byte) {
	box.Add(file, content)
}

// Get a file from box
func Get(file string) ([]byte, bool) {
	return box.Get(file)
}
