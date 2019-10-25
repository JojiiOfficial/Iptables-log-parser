package main

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

//LogEntry a entry in log
type LogEntry struct {
	Time                                           time.Time
	In, Out, Mac, Src, Dst, Len, TTL, ID, Protocol string
	DestPort, SrcPort                              int
}

/*ParseFileByLines parses a file and calls the given callback each time it found a LogEntry*/
func ParseFileByLines(filename string, callback func(*LogEntry)) error {
	logFile, err := os.Open(filename)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(logFile)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		if len(strings.Trim(line, " ")) == 0 {
			continue
		}
		logEntry, err := parseLogEntry(line)
		if err == nil {
			callback(logEntry)
		}
	}

	logFile.Close()
	return nil
}

//ParseFile parses a file and returns an array with all found entries
func ParseFile(filename string) ([]LogEntry, error) {
	var logs []LogEntry
	err := ParseFileByLines(filename, func(e *LogEntry) {
		logs = append(logs, *e)
	})
	if err != nil {
		return nil, err
	}
	return logs, nil
}

func parseLogEntry(content string) (*LogEntry, error) {
	if !strings.Contains(content, "Tripwire") {
		return nil, errors.New("not a tripwire log")
	}
	logItems := strings.Split(content, " ")
	entry := &LogEntry{}
	for _, val := range logItems {
		handleLogEntry(val, entry)
	}
	t, _ := time.Parse(time.Stamp, logItems[0]+" "+logItems[1]+" "+logItems[2])
	t = t.AddDate(time.Now().Year(), 0, 0)
	entry.Time = t
	return entry, nil
}

func handleLogEntry(data string, entry *LogEntry) {
	key, val, err := parseItem(data)
	if err != nil {
		return
	}
	switch key {
	case "IN":
		entry.In = val
	case "OUT":
		entry.Out = val
	case "MAC":
		entry.Mac = val
	case "SRC":
		entry.Src = val
	case "DST":
		entry.Dst = val
	case "LEN":
		entry.Len = val
	case "TTL":
		entry.TTL = val
	case "ID":
		entry.ID = val
	case "PROTO":
		entry.Protocol = val
	case "DPT":
		port, err := strconv.Atoi(val)
		if err == nil {
			entry.DestPort = port
		}
	case "SPT":
		port, err := strconv.Atoi(val)
		if err == nil {
			entry.SrcPort = port
		}
	}
}

func parseItem(item string) (string, string, error) {
	if !strings.Contains(item, "=") {
		return "", "", errors.New("no valid item")
	}
	data := strings.Split(item, "=")
	if len(data) != 2 {
		return "", "", errors.New("no data given")
	}
	return data[0], data[1], nil
}
