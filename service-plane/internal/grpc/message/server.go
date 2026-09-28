package message

import messagev1 "kr0n.com/service-plane/gen/message/v1"

type Server struct {
	messagev1.UnimplementedMessageServiceServer
}

func NewServer() *Server {
	return &Server{}
}
