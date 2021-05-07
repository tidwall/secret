# secret

A simple utility for encrypting and decrypting data in Go. (AES-256-CFB)

## Install

```
go get github.com/tidwall/secret
```

## Example

```go
func main

import "github.com/tidwall/secret"

func main(){
    key := "hello world"
    data := []byte("hello jello")

    encdata, err := secret.Encrypt(key, data)
    if err != nil{
        panic(err)
    }

    decdata, err := secret.Decrypt("hello world", encdata)
    if err != nil{
        panic(err)
    }

    println(string(decdata))
}
// output:
// hello jello

```