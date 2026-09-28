package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	messagev1 "kr0n.com/service-plane/gen/message/v1"
	"kr0n.com/service-plane/internal/config"
	"kr0n.com/service-plane/internal/grpc/message"
	"kr0n.com/service-plane/internal/router"
)

func main() {
	config, err := config.LoadConfig()

	if err != nil {
		log.Fatalln("Could not load config", err)
	}

	go func() {
		router := router.NewRouter()
		srv := &http.Server{
			Addr:         fmt.Sprintf(":%s", config.PORT),
			Handler:      router,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		log.Println("Starting REST server on:", srv.Addr)
		err := srv.ListenAndServe()

		if err != nil {
			log.Fatalln("Server failed to start: ", err)
		}
	}()

	go func() {

		lis, err := net.Listen("tcp", fmt.Sprintf(":%s", config.GRPC_PORT))

		if err != nil {
			log.Fatalln("Unable to create listener: ", err)
		}

		grpcServer := grpc.NewServer()
		messageServer := message.NewServer()
		messagev1.RegisterMessageServiceServer(grpcServer, messageServer)

		log.Println("Starting grpc server on:", config.GRPC_PORT)

		err = grpcServer.Serve(lis)

		if err != nil {
			log.Fatalln("Unable to start grpc server...", err)
		}

	}()

	errChan := make(chan os.Signal, 1)

	signal.Notify(errChan, os.Interrupt, syscall.SIGTERM)

	<-errChan

}
