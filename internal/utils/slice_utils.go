// Package utils
package utils

func ReverseForEach[T any](slice []T, f func(index int, value T)) {
	for i := len(slice) - 1; i >= 0; i-- {
		f(i, slice[i])
	}
}

func Find[T any](src []T, comparator func(element T) bool) T {
	for _, v := range src {
		if comparator(v) {
			return v
		}
	}
	var zero T
	return zero
}

func Filter[T any](src []T, filter func(element T) bool) (result []T) {
	result = make([]T, 0, len(src))
	for _, v := range src {
		if filter(v) {
			result = append(result, v)
		}
	}
	return
}

func Map[T any, R any](src []T, mapper func(element T) R) (result []R) {
	result = make([]R, len(src))
	for i, v := range src {
		result[i] = mapper(v)
	}
	return
}

func ForEach[T any](src []T, callback func(index int, element T)) {
	for i, v := range src {
		callback(i, v)
	}
}
