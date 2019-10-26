package examles

import (
	"fmt"

	iptablesparser "github.com/JojiiOfficial/Iptables-log-parser"
)

func main() {
	//examle for reading the file line by line
	err := iptablesparser.ParseFileByLines("/var/log/Tripwire21", func(log *iptablesparser.LogEntry) {
		fmt.Println(log)
	})
	if err != nil {
		panic(err)
	}

	//examle for reading the file and use the array
	logs, err := iptablesparser.ParseFile("/var/log/Tripwire21")
	if err != nil {
		panic(err)
	}
	for _, log := range logs {
		fmt.Println(log)
	}
}
