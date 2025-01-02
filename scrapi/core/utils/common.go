/*
 *  COPYRIGHT NOTICE
 *  All source code contained within the Scrapi asset and risk management software provided by (Company)
 *  is the copyright of the Company and protected by copyright laws. Redistribution or reproduction of
 *  this material is strictly prohibited without prior written permission of the Company. All rights reserved.
 */
package utils

import (
	"time"
)

const Joiner string = ", "

func GetDate() string {
	return time.Now().UTC().Format("2006-01-02")
}

func GetTime() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}

func GetTimeRaw() time.Time {
	return time.Now().UTC()
}

func GetTimeForBOM() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func IntContains(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func StrContains(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func MakeRange(min, max int) []int {
	a := make([]int, max-min+1)
	for i := range a {
		a[i] = min + i
	}
	return a
}
