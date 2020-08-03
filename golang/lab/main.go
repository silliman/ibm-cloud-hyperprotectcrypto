package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	plain := "Hello, this is a very long and creative message without any imagination"
	args := os.Args
	//	fmt.Println(args)
	//	fmt.Println(args[1:])
	//	fmt.Printf("%d args passed\n", len(args))
	// Basic flag declarations are available for string,
	// integer, and boolean options. Here we declare a
	// string flag `word` with a default value `"foo"`
	// and a short description. This `flag.String` function
	// returns a string pointer (not a string value);
	// we'll see how to use this pointer below.
	//wordPtr := flag.String("word", "foo", "a string")

	// This declares `numb` and `fork` flags, using a
	// similar approach to the `word` flag.
	//numbPtr := flag.Int("numb", 42, "an int")
	//boolPtr := flag.Bool("fork", false, "a bool")
	boolEx1Ptr := flag.Bool("ex1", false, "run exercise 1")
	boolEx2Ptr := flag.Bool("ex2", false, "run exercise 2")
	numbEx2KeyLenPtr := flag.Int("keyLength", 256, "length in bits")
	strEx2PlaintextPtr := flag.String("plaintext", plain, "plaintext to encrypt and decrypt")
	strGREP11srvrPtr := flag.String("server", address, "GREP11 server to connect to")

	boolEx3Ptr := flag.Bool("ex3", false, "run exercise 3")
	strEx3CurvePtr := flag.String("curve", "P521", "elliptic curve name")

	boolEx4Ptr := flag.Bool("ex4", false, "run exercise 4")
	boolEx4WrapPtr := flag.Bool("wrap", true, "force error on WrapKey by setting to false")
	boolEx4UnWrapPtr := flag.Bool("unwrap", true, "force error on UnwrapKey by setting to false")

	// It's also possible to declare an option that uses an
	// existing var declared elsewhere in the program.
	// Note that we need to pass in a pointer to the flag
	// declaration function.
	var svar string
	flag.StringVar(&svar, "svar", "bar", "a string var")

	// Once all flags are declared, call `flag.Parse()`
	// to execute the command-line parsing.
	flag.Parse()

	// Here we'll just dump out the parsed options and
	// any trailing positional arguments. Note that we
	// need to dereference the pointers with e.g. `*wordPtr`
	// to get the actual option values.
	/* 	fmt.Println("word:", *wordPtr)
	   	fmt.Println("numb:", *numbPtr)
	   	fmt.Println("fork:", *boolPtr)
	   	fmt.Println("svar:", svar)
	   	fmt.Println("tail:", flag.Args()) */
	if len(args) == 1 {
		fmt.Println("")
		fmt.Println("./lab [--ex1] [--ex2] [--ex3] [--ex4]")
		fmt.Println("")
		fmt.Println("\t--ex1 to run Exercise 1")
		fmt.Println("\t--ex2 to run Exercise 2")
		fmt.Println("\t--ex3 to run Exercise 3")
		fmt.Println("\t--ex4 to run Exercise 4")
		fmt.Println("")
	}
	if *boolEx1Ptr {
		getMechanismInfo(*strGREP11srvrPtr)
	}
	if *boolEx2Ptr {
		encryptAndDecrypt(*strGREP11srvrPtr, *numbEx2KeyLenPtr, *strEx2PlaintextPtr)
	}
	if *boolEx3Ptr {
		signAndVerifyUsingECDSAKeyPair(*strGREP11srvrPtr, *strEx3CurvePtr)
	}
	if *boolEx4Ptr {
		wrapAndUnwrapKey(*strGREP11srvrPtr, *boolEx4WrapPtr, *boolEx4UnWrapPtr)
	}
	

}
