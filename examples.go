package iptablesparser

import "fmt"

func main() {
	//examle for reading the file line by line
	err := ParseFileByLines("/var/log/Tripwire21", func(log *LogEntry) {
		fmt.Println(log)
	})
	if err != nil {
		panic(err)
	}

	//examle for reading the file and use the array
	logs, err := ParseFile("/var/log/Tripwire21")
	if err != nil {
		panic(err)
	}
	for _, log := range logs {
		fmt.Println(log)
	}
}
