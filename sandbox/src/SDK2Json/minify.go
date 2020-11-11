package main

import (
	"regexp"
)

const (
	paramIn uint8 = iota
	paramOut
	paramInOut
	paramReserved
)

const (
	typeImm uint8 = iota
	typePtrImm
	typePtrStr
	typePtrStruct
)

// APIParamMini represents a paramter of a Win32 API.
type APIParamMini struct {
	Annotation uint8  `json:"anno"`
	Type       uint8  `json:"type"`
	Name       string `json:"name"`
}

// APIMini represents information about a Win32 API.
type APIMini struct {
	Params          []APIParamMini `json:"params"` // API Arguments.
	ReturnValueType string         `json:"retVal"` // Return value type.
}

var (
	reAnnotationIn       = regexp.MustCompile(`_In_|_In_opt[\w]+|In_reads[\w()]+`)
	reAnnotationOut      = regexp.MustCompile(`_Out_|_Out_opt_[\w]+|_Out_writes[\w()]+|_Outptr_`)
	reAnnotationIntOut   = regexp.MustCompile(`_Inout[\w]+`)
	reAnnotationReserved = regexp.MustCompile(`Reserved`)
)

func minifyAPIs(apis map[string]map[string]API) map[string]map[string]APIMini {
	mapis := make(map[string]map[string]APIMini)
	for dllname, v := range apis {
		if _, ok := mapis[dllname]; !ok {
			mapis[dllname] = make(map[string]APIMini)
		}
		for apiname, vv := range v {
			copy := APIMini{
				ReturnValueType: vv.ReturnValueType}

			var paramsMini []APIParamMini
			for _, param := range vv.Params {
				parammini := APIParamMini{}
				if reAnnotationIn.MatchString(param.Annotation) {
					parammini.Annotation = paramIn
				} else if reAnnotationOut.MatchString(param.Annotation) {
					parammini.Annotation = paramOut
				} else if reAnnotationIntOut.MatchString(param.Annotation) {
					parammini.Annotation = paramInOut
				} else if reAnnotationReserved.MatchString(param.Annotation) {
					parammini.Annotation = paramReserved
				} else {
					continue
				}
				parammini.Name = param.Name
				paramsMini = append(paramsMini, parammini)
			}
			copy.Params = paramsMini
			mapis[dllname][apiname] = copy
		}
	}

	return mapis
}
