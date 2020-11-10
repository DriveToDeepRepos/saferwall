package main

import (
	// "encoding/json"
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/saferwall/saferwall/pkg/utils"
)

const (
	// RegAPIs is a regex that extract API prototypes.
	RegAPIs = `(_Success_|WINBASEAPI|WINADVAPI|NTSTATUS|_Must_inspect_result_|BOOLEAN)[\d\w\s\)\(,\[\]\!*+=&<>/]+;`

	RegProto = `(?P<Attr>WINBASEAPI|WINADVAPI)?( )?(?P<RetValType>[A-Z]+) (?P<CallConv>WINAPI|APIENTRY) (?P<ApiName>[a-zA-Z0-9]+)\((?P<Params>.*)\);`

	RegApiParams = `(?P<Anno>_In_|_In_opt_|_Inout_opt_|_Out_|_Inout_|_Out_opt_|_Outptr_opt_|_Reserved_|_Out[\w(),+ *]+|_In[\w()]+) (?P<Type>[\w *]+) (?P<Name>[*a-zA-Z0-9]+)`

	RegParam = `(, )_`

	RegDllName = `req\.dll: (?P<DLL>[\w]+\.dll)`
)

// APIParam represents a paramter of a Win32 API.
type APIParam struct {
	Annotation string `json:"anno"`
	Type       string `json:"type"`
	Name       string `json:"name"`
}

// API represents information about a Win32 API.
type API struct {
	Attribute         string     `json:"attr"`        // Microsoft-specific attribute.
	CallingConvention string     `json:"callConv"`    // Calling Convention.
	Name              string     `json:"name"`        // Name of the API.
	Params            []APIParam `json:"params"`      // API Arguments.
	CountParams       uint8      `json:"countParams"` // Count of Params.
	ReturnValueType   string     `json:"retVal"`      // Return value type.
}

func regSubMatchToMapString(regEx, s string) (paramsMap map[string]string) {

	r := regexp.MustCompile(regEx)
	match := r.FindStringSubmatch(s)

	paramsMap = make(map[string]string)
	for i, name := range r.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}
	return
}

func parseAPIParameter(params string) APIParam {
	m := regSubMatchToMapString(RegApiParams, params)
	apiParam := APIParam{
		Annotation: m["Anno"],
		Name:       m["Name"],
		Type:       m["Type"],
	}
	return apiParam
}

func parseAPI(apiPrototype string) API {
	m := regSubMatchToMapString(RegProto, apiPrototype)
	api := API{
		Attribute:         m["Attr"],
		CallingConvention: m["CallConv"],
		Name:              m["ApiName"],
		ReturnValueType:   m["RetValType"],
	}

	// Treat the VOID case.
	if m["Params"] == " VOID " {
		api.CountParams = 0
		return api
	}

	if api.Name == "BCryptEncrypt" {
		log.Println("ReadFile")
	}

	re := regexp.MustCompile(RegParam)
	split := re.Split(m["Params"], -1)
	for _, v := range split {
		api.Params = append(api.Params, parseAPIParameter("_"+v))
		api.CountParams++
	}
	return api
}

func removeAnnotations(apiPrototype string) string {
	apiPrototype = strings.Replace(apiPrototype, "_Must_inspect_result_", "", -1)
	apiPrototype = strings.Replace(apiPrototype, "_Success_(return != 0 && return < nBufferLength)", "", -1)
	apiPrototype = strings.Replace(apiPrototype, "_Success_(return != 0 && return < cchBuffer)", "", -1)
	return apiPrototype
}

func standardizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// WriteStrSliceToFile writes a slice of string line by line to a file.
func WriteStrSliceToFile(filename string, data []string) (int, error) {
	// Open a new file for writing only
	file, err := os.OpenFile(
		filename,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0666,
	)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	// Create a new writer.
	w := bufio.NewWriter(file)
	nn := 0
	for _, s := range data {
		n, _ := w.WriteString(s + "\n")
		nn += n
	}

	w.Flush()
	return nn, nil
}

// Read a whole file into the memory and store it as array of lines
func readLines(path string) (lines []string, err error) {

	var (
		part   []byte
		prefix bool
	)

	// Start by getting a file descriptor over the file
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	buffer := bytes.NewBuffer(make([]byte, 0))
	for {
		if part, prefix, err = reader.ReadLine(); err != nil {
			break
		}
		buffer.Write(part)
		if !prefix {
			lines = append(lines, buffer.String())
			buffer.Reset()
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}

// Exists reports whether the named file or directory exists.
func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// SliceContainsStringReverse returns if slice contains substring
func SliceContainsStringReverse(a string, list []string) bool {
	for _, b := range list {
		if strings.Contains(a, b) {
			return true
		}
	}
	return false
}

func getDLLName(file, apiname, sdkpath string) (string, error) {
	cat := strings.TrimSuffix(filepath.Base(file), ".h")
	functionName := "nf-" + cat + "-" + strings.ToLower(apiname) + ".md"
	mdFile := path.Join(sdkpath, "sdk-api-src", "content", cat, functionName)
	mdFileContent, err := utils.ReadAll(mdFile)
	if err != nil {
		log.Printf("Failed to find file: %s", mdFile)
		return "", err
	}
	m := regSubMatchToMapString(RegDllName, string(mdFileContent))
	return strings.ToLower(m["DLL"]), nil
}

func main() {

	// Parse arguments.
	// C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\
	sdkumPath := flag.String("sdk", "", "The path to the windows sdk directory")
	// https://github.com/MicrosoftDocs/sdk-api
	sdkapiPath := flag.String("sdk-api", "sdk-api", "The path to the sdk-api docs directory")

	hookapisPath := flag.String("hookapis", "hookapis.txt", "The path to a a text file which define which APIs to trace, new line separated.")

	flag.Parse()
	if *sdkumPath == "" {
		flag.Usage()
		os.Exit(0)
	}

	if !Exists(*sdkumPath) {
		log.Fatal("sdk directory does not exist")
	}

	if !Exists(*sdkapiPath) {
		log.Fatal("sdk-api directory does not exist")
	}
	if !Exists(*hookapisPath) {
		log.Fatal("hookapis.txt does not exists")
	}

	// Read the list of APIs we are interested to keep.
	wantedAPIs, err := readLines(*hookapisPath)
	if err != nil {
		log.Fatalln(err)
	}
	if len(wantedAPIs) == 0 {
		log.Fatal("hookapis.txt is empty")
	}

	files, err := utils.WalkAllFilesInDir(*sdkumPath)
	if err != nil {
		log.Fatalln(err)
	}

	m := make(map[string]map[string]API)
	for _, file := range files {
		
		var prototypes []string
		log.Printf("Processing %s\n", file)

		if !strings.HasSuffix(file, "fileapi.h") &&
			!strings.HasSuffix(file, "aprocessthreadsapi.h") &&
			!strings.HasSuffix(file, "bcrypt.h") {
			continue
		}

		// Read Win32 include API headers.
		data, err := utils.ReadAll(file)
		if err != nil {
			log.Fatalln(err)
		}

		// Grab all API prototypes
		// 1. Ignore: FORCEINLINE
		r := regexp.MustCompile(RegAPIs)
		matches := r.FindAllString(string(data), -1)
		log.Println("Size:", len(matches))

		for _, v := range matches {
			prototype := removeAnnotations(v)
			prototype = standardizeSpaces(prototype)
			prototypes = append(prototypes, prototype)

			// Only parse APIs we want to hook.
			if !SliceContainsStringReverse(prototype, wantedAPIs) {
				continue
			}

			if strings.Contains(prototype, "BCryptEncrypt") {
				log.Println("asas")
			}

			// Parse the API prototype.
			papi := parseAPI(prototype)

			// Find which DLL this API belongs to. Unfortunately, the sdk does
			// not give you this information, we look into the sdk-api markdown
			// docs instead. (Normally, we could have parsed everything from
			// the md files, but they are missing the parameters type!)
			dllname, err := getDLLName(file, papi.Name, *sdkapiPath)
			if err != nil {
				continue
			}
			log.Print(dllname)
			if _, ok := m[dllname]; !ok {
				m[dllname] = make(map[string]API)
			}
			m[dllname][papi.Name] = papi
		}

		if len(prototypes) > 0 {
			// Write raw prototypes to a text file.
			WriteStrSliceToFile("prototypes-"+filepath.Base(file)+".inc", prototypes)
		}
	}

	if len(m) > 0 {
		// Marshall and write to json file.
		data, _ := json.MarshalIndent(m, "", " ")
		utils.WriteBytesFile("apis.json", bytes.NewReader(data))
	}
}
