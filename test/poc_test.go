package test

import (
	"AutoScan/pkg/poc"
	"github.com/kr/pretty"
	"testing"
)

func TestLoadAndValidateTemplate(t *testing.T) {
	template, errors := poc.LoadAndValidateTemplate("./poc_test.yaml")
	for _, err := range errors {
		t.Error(err)
	}
	pretty.Println(template)
}
func TestLoadYamlConfigs(t *testing.T) {
	configs, errors := poc.LoadYamlPoc("./pocYaml/")
	for _, err := range errors {
		t.Error(err)
	}
	pretty.Println(configs)
}
func TestUseOnePoc(t *testing.T) {
	dirPath := "./pocYaml/thinkphp5-rce-invokefunction.yaml "
	targetPath := "http://127.0.0.1/thinkphp5.0/public/"
	poc.UseOnePoc(targetPath, dirPath)
}
func TestAllPoc(t *testing.T) {
	dirPath := "./pocYaml/"
	targetPath := "http://127.0.0.1/thinkphp5.0/public/"
	poc.UseAllPoc(targetPath, dirPath)
}
