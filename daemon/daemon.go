package main

import (
	"fmt"
	"time"
)

func main() {
	// go func() {
	for i := 1; i < 10; i++ {
		time.Sleep(1 * time.Second)
		fmt.Println("hello world", time.Now().Format(time.RFC822Z))
	}
	//}()

	//ch := make(chan os.Signal, 10)
	//signal.Notify(ch, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	//for {
	//fmt.Println(<-ch)
	//}
}
