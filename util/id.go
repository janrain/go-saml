package util

import "github.com/nu7hatch/gouuid"

// ID generates a new ID from a V4 UUID
func ID() string {
	u, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return "_" + u.String()
}
