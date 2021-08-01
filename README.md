# Go Encryption Helpers

### Password Based Encryption
#### MD5 and Triple-DES
Sample :
```go
package main

import (
    "fmt"
    "github.com/arajhansa/goencrypt/pbs/md5andtdes"
)

func main() {
    salt := []byte{0xFF, 0x2B, 0x38, 0x30, 0xF8, 0x61, 0xEF, 0x99}
    password := "some_super_password"
    iterations := 222
    originalText := "to_encrypt_this"
    
    res, err := md5andtdes.Encrypt(password, iterations, originalText, salt)
    fmt.Println("encrypted", res, err)
    res, err = md5andtdes.Decrypt(password, iterations, res, salt)
    fmt.Println("decrypted", res, err)
}
```
Output : 
```shell
encrypted jQ0LqwNaMiyz/V9P7OQJuuJccZIvjgpS <nil>
decrypted to_encrypt_this <nil>
```
