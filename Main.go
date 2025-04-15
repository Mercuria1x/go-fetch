package main

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// 配置文件路径
	configPath string
	// 配置
	config Config

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
		},
		Timeout: 30 * time.Second,
	}
)

func init() {
	// 定义命令行参数
	flag.StringVar(&configPath, "config", "config.json", "config文件路径")
}

type Config struct {
	//服务监听的端口号
	Port string `json:"port"`
	//监听路径
	Path string `json:"path"`
	//用于 token 校验的密钥
	Secret string `json:"secret"`
	//免 token 校验的白名单域名
	WhiteListDomains []string `json:"whiteListDomains"`
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func main() {
	flag.Parse()

	// 从环境变量中获取配置下载链接
	configUrl := os.Getenv("GO_FETCH_CONFIG_URL")
	log.Printf("GO_FETCH_CONFIG_URL:%s\n", configUrl)
	if configUrl != "" {
		err := downloadFile(configUrl, configPath)
		if err != nil {
			log.Fatalf("下载配置文件失败: %v", err)
			return
		}
	}

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	http.HandleFunc(config.Path, fetchHandler)

	log.Printf("secret :%s", config.Secret)
	log.Printf("whiteListDomains :%s", config.WhiteListDomains)
	log.Printf("服务启动，监听 http://0.0.0.0:%s%s", config.Port, config.Path)
	if err := http.ListenAndServe(":"+config.Port, nil); err != nil {
		log.Fatal("ListenAndServe 出错: ", err)
	}
}

// fetchHandler 处理请求
func fetchHandler(w http.ResponseWriter, r *http.Request) {
	// 1. 判断是否存在查询参数 url
	targetUrl := r.URL.Query().Get("url")
	if targetUrl == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 2. 解析目标 URL
	parsedTargetUrl, err := url.Parse(targetUrl)
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	// 3. 检查目标 URL 的 host 是否在白名单中
	needTokenCheck := true
	for _, domain := range config.WhiteListDomains {
		// 使用后缀匹配
		if strings.HasSuffix(parsedTargetUrl.Hostname(), strings.TrimSpace(domain)) {
			needTokenCheck = false
			break
		}
	}

	// 4. 如果目标域名不在白名单中，则需要验证 token
	if needTokenCheck {
		tVal := r.URL.Query().Get("t")
		token := r.URL.Query().Get("token")
		if tVal == "" || token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		data := tVal + config.Secret + targetUrl
		h := sha1.New()
		h.Write([]byte(data))
		computedToken := hex.EncodeToString(h.Sum(nil))
		//log.Printf("计算 token: %s", computedToken)
		if computedToken != token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// 5. 构造转发请求
	req, err := http.NewRequest(r.Method, targetUrl, r.Body)
	// 初始化 Header
	req.Header = make(http.Header)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 拷贝原请求头，删除部分敏感头
	for name, values := range r.Header {
		if isSkipHeader(name) {
			continue
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	req.Header.Del("Host")
	req.Host = parsedTargetUrl.Host

	// 6. 转发请求并获取响应
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 7. 将目标响应头复制到客户端响应中
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	buf := make([]byte, 32*1024) // 32KB 缓冲区
	if _, err := io.CopyBuffer(w, resp.Body, buf); err != nil {
		log.Println("复制响应体出错:", err)
	}
}

// isSkipHeader 判断是否为需要删除的请求头
func isSkipHeader(header string) bool {
	skipHeaders := []string{
		"cf-connecting-ip",
		"cf-ipcountry",
		"cf-visitor",
		"cf-ray",
		"x-real-ip",
		"x-forwarded-proto",
	}
	header = strings.ToLower(header)
	for _, h := range skipHeaders {
		if header == strings.ToLower(h) {
			return true
		}
	}
	return false
}

// 下载文件
func downloadFile(url string, filePath string) error {
	// 创建文件夹（如果不存在）
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("无法创建目录: %v", err)
	}

	// 创建文件
	out, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer out.Close()

	// 获取数据
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("下载请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查服务器响应
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	// 写入文件
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	return nil
}
