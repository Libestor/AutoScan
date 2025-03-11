package poc

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"requests"`
	Vail     bool
}

type Info struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

type Request struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Body              string            `yaml:"body"`
	Headers           map[string]string `yaml:"headers"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []Matcher         `yaml:"matchers"`
}

type Matcher struct {
	Type      string   `yaml:"type"`
	Words     []string `yaml:"words,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
}

// ValidationError 定义验证错误类型
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error: field %s %s", e.Field, e.Message)
}

// LoadAndValidateTemplate 解析并验证
func LoadAndValidateTemplate(path string) (*Template, []error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, []error{fmt.Errorf("文件读取失败: %w", err)}
	}

	var tpl Template
	if err := yaml.Unmarshal(data, &tpl); err != nil {
		return nil, []error{fmt.Errorf("YAML %s 解析失败: %w", path, err)}
	}

	return &tpl, tpl.Validate()
}

// Validate 验证POC文件
func (t *Template) Validate() []error {
	var errors []error

	// ID
	if t.ID == "" {
		errors = append(errors, ValidationError{Field: "id", Message: "不能为空"})
		t.Vail = false
	}
	// info
	if t.Info.Name == "" {
		errors = append(errors, ValidationError{Field: "info.name", Message: "不能为空"})
		t.Vail = false
	}
	// 严重性
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	if !validSeverities[strings.ToLower(t.Info.Severity)] {
		errors = append(errors, ValidationError{
			Field:   "info.severity",
			Message: fmt.Sprintf("无效值 '%s'，应为 critical/high/medium/low/info", t.Info.Severity),
		})
		t.Vail = false
	}
	for i, req := range t.Requests {
		prefix := fmt.Sprintf("requests[%d]", i)
		// HTTP
		validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true}
		if !validMethods[strings.ToUpper(req.Method)] {
			errors = append(errors, ValidationError{
				Field:   prefix + ".method",
				Message: fmt.Sprintf("无效方法 '%s'", req.Method),
			})
			t.Vail = false
		}

		// 路径变量
		for _, path := range req.Path {
			if path == "" {
				errors = append(errors, ValidationError{
					Field:   prefix + ".path",
					Message: "路径不能为空",
				})
				t.Vail = false
			}
		}
		// 匹配器
		for j, matcher := range req.Matchers {
			matcherPrefix := fmt.Sprintf("%s.matchers[%d]", prefix, j)
			switch matcher.Type {
			case "word":
				if len(matcher.Words) == 0 {
					errors = append(errors, ValidationError{
						Field:   matcherPrefix + ".words",
						Message: "word类型必须包含匹配词",
					})
					t.Vail = false
				}
			case "status":
				for _, status := range matcher.Status {
					if status < 100 || status >= 600 {
						errors = append(errors, ValidationError{
							Field:   matcherPrefix + ".status",
							Message: fmt.Sprintf("无效HTTP状态码 %d", status),
						})
						t.Vail = false
					}
				}
			case "regex":
				if matcher.Condition == "" {
					errors = append(errors, ValidationError{
						Field:   matcherPrefix + ".condition",
						Message: "regex类型必须包含条件",
					})
					t.Vail = false
				}
			default:
				errors = append(errors, ValidationError{
					Field:   matcherPrefix + ".type",
					Message: fmt.Sprintf("未知匹配类型 '%s'", matcher.Type),
				})
				t.Vail = false
			}
		}
	}
	t.Vail = true
	return errors
}

// LoadYamlPoc 加载配置
func LoadYamlPoc(dirPath string) ([]*Template, []error) {
	var (
		wg         sync.WaitGroup
		configChan = make(chan *Template)
		errorChan  = make(chan error)
		configYaml []*Template
		errors     []error
	)

	// 扫描目录
	files, err := getYamlFiles(dirPath)
	if err != nil {
		return nil, []error{err}
	}

	// 结果收集
	go func() {
		for cfg := range configChan {
			configYaml = append(configYaml, cfg)
		}
	}()
	go func() {
		for err := range errorChan {
			errors = append(errors, err)
		}
	}()

	// 并发解析
	for _, file := range files {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			cfg, err := LoadAndValidateTemplate(path)
			configChan <- cfg
			for _, err := range err {
				errorChan <- err
			}
		}(file)
	}

	wg.Wait()
	close(configChan)
	close(errorChan)
	return configYaml, errors
}

// getYamlFiles 获取YAML文件列表
func getYamlFiles(dir string) ([]string, error) {
	var yamlFiles []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("目录读取失败: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && isYamlFile(entry.Name()) {
			yamlFiles = append(yamlFiles, filepath.Join(dir, entry.Name()))
		}
	}

	return yamlFiles, nil
}

// isYamlFile 文件扩展名检测
func isYamlFile(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".yaml" || ext == ".yml"
}
