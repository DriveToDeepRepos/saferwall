package main

import (
	"log"

	"regexp"
	"strings"
)

const (
	// RegAPIs is a regex that extract API prototypes.
	RegAPIs = `(_Success_|HANDLE|INTERNETAPI|BOOLAPI|BOOL|STDAPI|WINUSERAPI|WINBASEAPI|WINADVAPI|NTSTATUS|_Must_inspect_result_|BOOLEAN)[\d\w\s\)\(,\[\]\!*+=&<>/|]+;`

	// RegProto extracts API information.
	RegProto = `(?P<Attr>WINBASEAPI|WINADVAPI)?( )?(?P<RetValType>[A-Z]+) (?P<CallConv>WINAPI|APIENTRY) (?P<ApiName>[a-zA-Z0-9]+)( )?\((?P<Params>.*)\);`

	// RegAPIParams parses params.
	RegAPIParams = `(?P<Anno>_In_|_In_opt_|_Inout_opt_|_Out_|_Inout_|_Out_opt_|_Outptr_opt_|_Reserved_|_Out[\w(),+ *]+|_In[\w()]+) (?P<Type>[\w *]+) (?P<Name>[*a-zA-Z0-9]+)`
)

// APIParam represents a paramter of a Win32 API.
type APIParam struct {
	Annotation string `json:"anno"`
	Type       string `json:"type"`
	Name       string `json:"name"`
}

// API represents information about a Win32 API.
type API struct {
	Attribute         string     `json:"-"`      // Microsoft-specific attribute.
	CallingConvention string     `json:"-"`      // Calling Convention.
	Name              string     `json:"-"`      // Name of the API.
	Params            []APIParam `json:"params"` // API Arguments.
	CountParams       uint8      `json:"-"`      // Count of Params.
	ReturnValueType   string     `json:"retVal"` // Return value type.
}

func parseAPIParameter(params string) APIParam {
	m := regSubMatchToMapString(RegAPIParams, params)
	apiParam := APIParam{
		Annotation: m["Anno"],
		Name:       m["Name"],
		Type:       m["Type"],
	}

	// move the `*` to the type.
	if strings.HasPrefix(apiParam.Name, "*") {
		apiParam.Name = apiParam.Name[1:]
		apiParam.Type += "*"
	}

	return apiParam
}

func parseAPI(apiPrototype string) API {
	if strings.Contains(apiPrototype, "Process32NextW") {
		log.Print()
	}
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

	if api.Name == "" || api.CallingConvention == "" {
		log.Printf("Failed to parse: %s", apiPrototype)
	}
	re := regexp.MustCompile(RegParam)
	split := re.Split(m["Params"], -1)
	for i, v := range split {
		// Quick hack:
		ss := strings.Split(standardizeSpaces(v), " ")
		if len(ss) == 2 {
			// Force In for API without annotations.
			v = "_In_ " + v
		} else {
			if i+1 < len(split) {
				vv := standardizeSpaces(split[i+1])
				if !strings.HasPrefix(vv, "In") &&
					!strings.HasPrefix(vv, "Out") &&
					!strings.HasPrefix(vv, "_In") &&
					!strings.HasPrefix(vv, "_Reserved") &&
					!strings.HasPrefix(vv, "_Out") {
					v += " " + split[i+1]
					split[i+1] = v
					continue
				}
			}
		}
		api.Params = append(api.Params, parseAPIParameter("_"+v))
		api.CountParams++
	}
	return api
}
