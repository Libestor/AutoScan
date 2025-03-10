package utils

import (
	Spider "AutoScan/pkg/spider"
	"github.com/go-resty/resty/v2"
	"sync"
)

var DEFAULT_PARAM = "1"

type Client struct {
	Client *resty.Client
	mu     sync.Mutex
}

// 获取请求
func GetParams(info Spider.RequestInfo) map[string]string {
	params := make(map[string]string)
	//params := make(sync.Map)
	for param, _ := range info.Params {
		if len(info.Params[param]) == 0 || info.Params[param][0] == "" {
			params[param] = DEFAULT_PARAM
		}
		params[param] = info.Params[param][0]
	}
	// 适配pikachu
	params["submit"] = "submit"
	return params
}

// 发送数据包
func (c *Client) Request(url string, method string, param map[string]string, requestType string) (*resty.Response, error) {
	c.mu.Lock()
	param["submit"] = "submit"
	c.mu.Unlock()
	if method == "GET" {
		return c.Get(url, param)
	} else {
		return c.Post(url, param, requestType)
	}
}
func (c *Client) Get(url string, param map[string]string) (*resty.Response, error) {
	tmp := c.Client.R()
	c.mu.Lock()
	tmp.SetQueryParams(param)
	c.mu.Unlock()
	return tmp.Get(url)

}
func (c *Client) Post(url string, param map[string]string, requestType string) (*resty.Response, error) {
	tmp := c.Client.R()
	c.mu.Lock()
	if requestType == "application/json" {
		tmp.SetBody(param)
	} else {
		tmp.SetFormData(param)
	}
	c.mu.Unlock()
	return tmp.Post(url)
}
