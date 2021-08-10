package jsonnet

import (
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	jsonnet "github.com/google/go-jsonnet"
	"github.com/pkg/errors"

	"github.com/grafana/tanka/pkg/jsonnet/jpath"
	"github.com/grafana/tanka/pkg/jsonnet/native"
)

var fileHashes sync.Map

// Modifier allows to set optional parameters on the Jsonnet VM.
// See jsonnet.With* for this.
type Modifier func(vm *jsonnet.VM) error

// InjectedCode holds data that is "late-bound" into the VM
type InjectedCode map[string]string

// Set allows to set values on an InjectedCode, even when it is nil
func (i *InjectedCode) Set(key, value string) {
	if *i == nil {
		*i = make(InjectedCode)
	}

	(*i)[key] = value
}

// Opts are additional properties for the Jsonnet VM
type Opts struct {
	ExtCode     InjectedCode
	TLACode     InjectedCode
	ImportPaths []string
	EvalScript  string

	CachePath           string
	CacheEnvRegexes     []*regexp.Regexp
	WarnLongEvaluations time.Duration
}

// Clone returns a deep copy of Opts
func (o Opts) Clone() Opts {
	extCode, tlaCode := InjectedCode{}, InjectedCode{}

	for k, v := range o.ExtCode {
		extCode[k] = v
	}

	for k, v := range o.TLACode {
		tlaCode[k] = v
	}

	return Opts{
		TLACode:     tlaCode,
		ExtCode:     extCode,
		ImportPaths: append([]string{}, o.ImportPaths...),
		EvalScript:  o.EvalScript,
	}
}

// MakeVM returns a Jsonnet VM with some extensions of Tanka, including:
// - extended importer
// - extCode and tlaCode applied
// - native functions registered
func MakeVM(opts Opts) *jsonnet.VM {
	vm := jsonnet.MakeVM()
	vm.Importer(NewExtendedImporter(opts.ImportPaths))

	for k, v := range opts.ExtCode {
		vm.ExtCode(k, v)
	}
	for k, v := range opts.TLACode {
		vm.TLACode(k, v)
	}

	for _, nf := range native.Funcs() {
		vm.NativeFunction(nf)
	}

	return vm
}

// EvaluateFile evaluates the Jsonnet code in the given file and returns the
// result in JSON form. It disregards opts.ImportPaths in favor of automatically
// resolving these according to the specified file.
func EvaluateFile(jsonnetFile string, opts Opts) (string, error) {
	bytes, _ := ioutil.ReadFile(jsonnetFile)
	return Evaluate(jsonnetFile, string(bytes), opts)

}

// Evaluate renders the given jsonnet into a string
func Evaluate(path, data string, opts Opts) (string, error) {
	// Create VM
	jpath, _, _, err := jpath.Resolve(path)
	if err != nil {
		return "", errors.Wrap(err, "resolving import paths")
	}
	opts.ImportPaths = jpath
	vm := MakeVM(opts)

	// Parse cache path and fetch from cache (if the item is there)
	var cachePath, scheme string
	if opts.CachePath != "" {
		envHash, err := getEnvHash(vm, path, data)
		if err != nil {
			return "", err
		}

		parts := strings.Split(opts.CachePath, "://")
		scheme, path := parts[0], parts[1]

		switch scheme {
		case "file":
			cachePath = filepath.Join(path, envHash+".json")
			if _, err := os.Stat(cachePath); err == nil {
				bytes, err := ioutil.ReadFile(cachePath)
				return string(bytes), err
			} else if !os.IsNotExist(err) {
				return "", err
			}
		case "gs":
		default:
			return "", errors.New("invalid cache path scheme: " + scheme)
		}
	}

	startTime := time.Now()
	content, err := vm.EvaluateAnonymousSnippet(path, data)
	if err != nil {
		return "", err
	}
	if opts.WarnLongEvaluations != 0 {
		if evalTime := time.Since(startTime); evalTime > opts.WarnLongEvaluations {
			log.Println(color.YellowString("[WARN] %s took %d to evaluate", path, evalTime.Seconds()))
		}
	}

	if opts.CachePath != "" {
		switch scheme {
		case "file":
			err = ioutil.WriteFile(cachePath, []byte(content), 0644)
		case "gs":
		}

	}

	return content, err
}

func getEnvHash(vm *jsonnet.VM, path, data string) (string, error) {
	node, _ := jsonnet.SnippetToAST(path, data)
	result := map[string]bool{}
	if err := importRecursive(result, vm, node, path); err != nil {
		return "", err
	}
	fileNames := []string{}
	for file := range result {
		fileNames = append(fileNames, file)
	}
	sort.Strings(fileNames)

	fullHasher := sha256.New()
	fullHasher.Write([]byte(data))
	for _, file := range fileNames {
		var fileHash []byte
		if got, ok := fileHashes.Load(file); ok {
			fileHash = got.([]byte)
		} else {
			bytes, err := os.ReadFile(file)
			if err != nil {
				return "", err
			}
			hash := sha256.New()
			fileHash = hash.Sum(bytes)
			fileHashes.Store(file, fileHash)
		}
		fullHasher.Write(fileHash)
	}

	return base64.URLEncoding.EncodeToString(fullHasher.Sum(nil)), nil
}
