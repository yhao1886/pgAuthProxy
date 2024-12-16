package main

import (
	log "github.com/sirupsen/logrus"
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
//	urlExample := "postgres://postgres:postgres@localhost:5432/postgres"
//	conn, err := pgx.Connect(context.Background(), urlExample)
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
//		os.Exit(1)
//	}
//	defer conn.Close(context.Background())
//
//	var name string
//	var weight int64
//	err = conn.QueryRow(context.Background(), "select name, weight from widgets where id=$1", 42).Scan(&name, &weight)
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "QueryRow failed: %v\n", err)
//		os.Exit(1)
//	}
//
//	fmt.Println(name, weight)
//}

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
//
//func handleConnection(conn net.Conn) {
//	defer conn.Close()
//
//	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
//
//	for {
//		msg, err := frontend.Receive()
//		if err != nil {
//			log.Printf("接收消息失败: %v", err)
//			return
//		}
//
//		log.Printf("收到消息: %#v", msg)
//
//		// 这里可以添加更多的处理逻辑
//	}
//}

//func main() {
//	// 模拟监听 PostgreSQL 客户端的连接
//	listener, err := net.Listen("tcp", "127.0.0.1:5432")
//	if err != nil {
//		fmt.Println("Failed to start server:", err)
//		return
//	}
//	defer listener.Close()
//
//	fmt.Println("Listening on 127.0.0.1:5432...")
//
//	for {
//		conn, err := listener.Accept()
//		if err != nil {
//			fmt.Println("Failed to accept connection:", err)
//			continue
//		}
//
//		go handleConnection(conn)
//	}
//}
//
//func handleConnection(conn net.Conn) {
//	defer conn.Close()
//
//	// 创建 Frontend 实例以解析客户端消息
//	frontend := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)
//
//	for {
//		// 接收客户端的消息
//		msg, err := frontend.Receive()
//		if err != nil {
//			fmt.Println("Error receiving message:", err)
//			return
//		}
//
//		switch msg := msg.(type) {
//		case *pgproto3.StartupMessage:
//			// 处理启动消息
//			fmt.Println("Received StartupMessage:", msg.Parameters)
//
//			// 发送身份验证请求 (AuthenticationCleartextPassword 或 AuthenticationMD5Password)
//			authRequest := &pgproto3.AuthenticationCleartextPassword{}
//			_, err := conn.Write(authRequest.Encode(nil))
//			if err != nil {
//				fmt.Println("Error sending authentication request:", err)
//				return
//			}
//
//		case *pgproto3.PasswordMessage:
//			// 获取客户端输入的密码
//			fmt.Println("Received PasswordMessage:")
//			fmt.Printf("Password: %s\n", string(msg.Password))
//
//			// 发送身份验证成功消息
//			authOK := &pgproto3.AuthenticationOk{}
//			_, err := conn.Write(authOK.Encode(nil))
//			if err != nil {
//				fmt.Println("Error sending authentication success:", err)
//				return
//			}
//
//			// 发送 ReadyForQuery 消息
//			readyForQuery := &pgproto3.ReadyForQuery{}
//			_, err = conn.Write(readyForQuery.Encode(nil))
//			if err != nil {
//				fmt.Println("Error sending ReadyForQuery:", err)
//				return
//			}
//			return
//
//		default:
//			fmt.Printf("Received unexpected message: %#v\n", msg)
//		}
//	}
//}
