package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jackc/pgproto3/v2"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"pgAuthProxy/auth"
	"pgAuthProxy/utils"
	"strings"
	"time"
)

type ProxyBack struct {
	TargetProps map[string]string
	TargetHost  string

	originProps      map[string]string
	backendConn      net.Conn
	proto            *pgproto3.Frontend
	protoChunkReader pgproto3.ChunkReader
}

const MaxTcpPayload = 65535

var (
	MissingRequiredTargetFields = errors.New("required target fields missing in target props")
	BackendAuthenticationError  = errors.New("backend authentication failed")
	BackendInvalidMessage       = errors.New("unexpected message received from backend")
)

func NewProxyBackend(targetProps map[string]string, originProps map[string]string) (*ProxyBack, error) {
	b := &ProxyBack{
		originProps: originProps,
		TargetProps: make(map[string]string),
	}
	if host, ok := targetProps[utils.TargetHostParameter]; ok {
		b.TargetHost = host
	} else {
		return nil, MissingRequiredTargetFields
	}
	for k, v := range targetProps {
		if !strings.HasPrefix(k, utils.MetaPrefix) {
			b.TargetProps[k] = v
		}
	}
	err := b.initiateBackendConnection(targetProps[utils.TargetCredentialParameter])
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (b *ProxyBack) initiateBackendConnection(credential string) error {
	conn, err := net.Dial("tcp", b.TargetHost)
	if err != nil {
		return err
	}
	b.backendConn = conn
	b.protoChunkReader = pgproto3.NewChunkReader(conn)
	b.proto = pgproto3.NewFrontend(b.protoChunkReader, conn)
	err = b.proto.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      b.TargetProps,
	})
	if err != nil {
		conn.Close()
		return err
	}
	for {
		msg, err := b.proto.Receive()
		if err != nil {
			conn.Close()
			return err
		}
		switch msg.(type) {
		case *pgproto3.AuthenticationMD5Password:
			salt := msg.(*pgproto3.AuthenticationMD5Password).Salt
			err = b.proto.Send(&pgproto3.PasswordMessage{Password: auth.SaltedMd5Credential(credential, salt)})
			if err != nil {
				conn.Close()
				return err
			}
			continue
		case *pgproto3.AuthenticationOk:
			return nil
		case *pgproto3.ErrorResponse:
			return BackendAuthenticationError
		case *pgproto3.AuthenticationSASL:
			fmt.Println("Support mechanisms:", msg.(*pgproto3.AuthenticationSASL).AuthMechanisms)
			clientNonce := "randomClientNonce123"
			initialMessage := fmt.Sprintf("n,,n=postgres,r=%s", clientNonce)
			err = b.proto.Send(&pgproto3.SASLInitialResponse{
				AuthMechanism: "SCRAM-SHA-256",
				Data:          []byte(initialMessage),
			})
			if err != nil {
				conn.Close()
				return err
			}
			continue

		case *pgproto3.AuthenticationSASLContinue:
			fmt.Println(string(msg.(*pgproto3.AuthenticationSASLContinue).Data))

		case *pgproto3.AuthenticationSASLFinal:
			continue
		default:
			conn.Close()
			fmt.Printf("initiateBackendConnection-msg: %+v", msg)
			return BackendInvalidMessage
		}
	}
}

func pipeBackendPgMessages(source pgproto3.ChunkReader, dest io.Writer) error {
	bw := utils.NewBufferedWriter(MaxTcpPayload, dest, 300*time.Millisecond)
	defer bw.Close()
	startupComplete := false

	for {
		header, err := source.Next(5)

		if err != nil {
			return err
		}
		l := int(binary.BigEndian.Uint32(header[1:])) - 4
		body, err := source.Next(l)
		fmt.Printf("===pipeBackendPgMessages===body: %+v, err: %+v\n", string(body), err)
		_, err = bw.Write(append(header, body...))
		if err != nil {
			return err
		}
		_, err = bw.Flush()
		if err != nil {
			return err
		}
		switch header[0] {
		case 'S':
			if !startupComplete {
				break
			}
			fallthrough
		case 'A', 'N', 'Z':
			if header[0] == 'Z' {
				startupComplete = true
			}
			_, err = bw.Flush()
			if err != nil {
				return err
			}
		}
	}
}

func pipePgMessages(source pgproto3.ChunkReader, dest io.Writer) error {
	for {
		header, err := source.Next(5)
		fmt.Printf("===pipePgMessages===header[0]1: %+v, err: %+v\n", header, err)
		if err != nil {
			return err
		}
		l := int(binary.BigEndian.Uint32(header[1:])) - 4
		body, err := source.Next(l)
		fmt.Printf("===pipePgMessages===header[0]2: %+v, body: %+v, err: %+v\n", header, string(body), err)
		_, err = dest.Write(append(header, body...))

		if err != nil {
			return err
		}
	}
}

func (b *ProxyBack) Run(frontConn net.Conn, frontChunkReader pgproto3.ChunkReader) error {
	defer b.Close()
	err := make(chan error)
	err1 := make(chan error)
	go func() {
		log.Debug("bootstrapped backend -> frontend message pipe")
		err <- pipeBackendPgMessages(b.protoChunkReader, frontConn)
		//_, e1 := io.Copy(frontConn, b.backendConn)
		//if err != nil {
		//	err <- e1
		//}
	}()

	go func() {
		log.Debug("bootstrapped backend <- frontend message pipe")
		err1 <- pipePgMessages(frontChunkReader, b.backendConn)
		//_, e2 := io.Copy(b.backendConn, frontConn)
		//if err != nil {
		//	err1 <- e2
		//}
	}()

	select {
	case e := <-err:
		log.Errorf("pipeBackendPgMessages backend err:%+v", e)
		return e
	case e1 := <-err1:
		log.Errorf("pipePgMessages backend err:%+v", e1)
		return e1
	}
}

func (b *ProxyBack) Close() {
	if b.backendConn != nil {
		b.backendConn.Close()
	}
}
