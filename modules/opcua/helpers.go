package opcua

import (
	"fmt"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"reflect"
)

func StatusCodeString(n ua.StatusCode) string {
	if d, ok := ua.StatusCodes[n]; ok {
		return fmt.Sprintf("%s", d.Name)
	}
	return fmt.Sprintf("0x%X", uint32(n))
}

func UAErrorDesc(err error) string {
	switch err.(type) {
	case ua.StatusCode:
		return StatusCodeString(err.(ua.StatusCode))
	case *uacp.Error:
		code := ua.StatusCode(err.(*uacp.Error).ErrorCode)
		return StatusCodeString(code)
	default:
		return ""
	}
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}

type InvalidResponseTypeError struct {
	got, want interface{}
}

func (e InvalidResponseTypeError) Error() string {
	return fmt.Sprintf("invalid response: got %T want %T", e.got, e.want)
}

// safeAssign implements a type-safe assign from T to *T.
func safeAssign(t, ptrT interface{}) error {
	if reflect.TypeOf(t) != reflect.TypeOf(ptrT).Elem() {
		return InvalidResponseTypeError{t, ptrT}
	}

	// this is *ptrT = t
	reflect.ValueOf(ptrT).Elem().Set(reflect.ValueOf(t))
	return nil
}
