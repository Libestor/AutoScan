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
func TestLoadYamlPoc(t *testing.T) {
	yamlPoc, errors := poc.LoadYamlPoc("./pocYaml/")
	for _, err := range errors {
		t.Error(err)
	}
	pretty.Println(yamlPoc)
}
