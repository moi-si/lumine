package errors

import "errors"

var New = errors.New

type opError struct {
	op  string
	err error
}

func (e *opError) Error() string {
	return e.op + ": " + e.err.Error()
}

func (e *opError) Unwrap() error {
	return e.err
}

func WithStr(op string, err error) error {
	return &opError{
		op:  op,
		err: err,
	}
}
