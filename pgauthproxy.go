package main

import (
	"github.com/jackc/pgproto3/v2"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"pgAuthProxy/cmd"
)

func main() {
	if err := cmd.RootCommand(); err != nil {
		log.WithError(err).Fatal("Application start failed")
		os.Exit(1)
	}
}

//func main() {
//	listener, err := net.Listen("tcp", "localhost:5432")
//	if err != nil {
//		log.Fatalf("无法启动服务器: %v", err)
//	}
//	defer listener.Close()
//
//	log.Println("服务器已启动，监听端口 5432")
//
//	for {
//		conn, err := listener.Accept()
//		if err != nil {
//			log.Printf("接受连接失败: %v", err)
//			continue
//		}
//
//		go handleConnection(conn)
//	}
//}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)

	for {
		msg, err := frontend.Receive()
		if err != nil {
			log.Printf("接收消息失败: %v", err)
			return
		}

		log.Printf("收到消息: %#v", msg)

		// 这里可以添加更多的处理逻辑
	}
}
