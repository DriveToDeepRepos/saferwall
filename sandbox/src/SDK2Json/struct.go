package main

import (
	"fmt"

	"github.com/dlclark/regexp2"
)

var (
	RegStructs = `typedef [\w() ]*struct [\w]+[\n\s]+{(.|\n)+?} (?!DUMMYSTRUCTNAME|DUMMYUNIONNAME)[\w, *]+;`

	RegParseStruct = `typedef [\w() ]*struct ([\w]+[\n\s]+){((.|\n)+?)} (?!DUMMYSTRUCTNAME|DUMMYUNIONNAME)([\w, *]+);`
)

type StructMember struct {
	Name string
	Type string
}

type Struct struct {
	Members []StructMember
}

func parseStruct(def string) Struct {

	r := regexp2.MustCompile(RegParseStruct, 0)
	if m, _ := r.FindStringMatch(def); m != nil {
		// the whole match is always group 0
		fmt.Printf("Group 0: %v\n", m.String())
	
		gps := m.Groups()
		fmt.Println(gps[1].Capture.String())
		fmt.Println(gps[2].Capture.String())
		// fmt.Println(gps[3].Capture.String())
		fmt.Println(gps[4].Capture.String())
	}

	return Struct{}
}

func getAllStructs(data string) []string {

	r := regexp2.MustCompile(RegStructs, 0)
	matches := regexp2FindAllString(r, string(data))
	for _, m := range matches {
		structObj := parseStruct(m)
		fmt.Println(structObj)	
	}
	return matches
}
