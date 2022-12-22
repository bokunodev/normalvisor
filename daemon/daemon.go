package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	go func() {
		for {
			time.Sleep(1 * time.Second)
			fmt.Println("hello world", time.Now().Format(time.RFC822Z))
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println(<-ch)
}
