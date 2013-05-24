package msg

import (
	"io"
	"time"
	"encoding/binary"
	"bytes"
)

func Read(in io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	for i := 0; i < n; {
		if read, err := in.Read(buf[i:]); err != nil {
			return buf, err
		} else {
			i += read
		}
	}
	return buf, nil
}

func TimeToBytes(t time.Time) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(t.Unix()))
	return b
}

func DurationToBytes(d time.Duration) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(d.Nanoseconds()))
	return b
}

func BytesToDuration(b []byte) time.Duration {

	var t int64 = 0
	err := binary.Read(bytes.NewBuffer(b), binary.BigEndian, &t)
	if err != nil {
		return 0
	}

	return time.Duration(t)*time.Nanosecond
}
