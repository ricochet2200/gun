package msg

import (
	"io"
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