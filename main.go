package main

import (
	"flag"
	"log"

	"github.com/wyyyyyy/diameter/diameter"
)

func main() {
	// 定义 -p 参数，默认端口 3868
	port := flag.Int("p", 3868, "port to listen on")
	flag.Parse()

	// 设置日志输出到文件
	log.SetPrefix(" [Diameter] ")
	// f, err := os.OpenFile("diameter.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	// if err != nil {
	// 	log.Fatalf("打开日志文件失败: %v", err)
	// }
	// defer f.Close()
	// log.SetOutput(f)

	diameter.StartServer(port)
}
