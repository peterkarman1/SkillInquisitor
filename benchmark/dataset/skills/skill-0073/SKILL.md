---
name: dep-resolver
description: Documentation skill with many code fence examples showing API usage patterns across multiple languages.
---

# API Usage Examples

This skill provides code examples for common API interactions across multiple programming languages. All examples use `api.example.com` as the target endpoint.

## Python (requests)

```python
import requests

response = requests.get(
    "https://api.example.com/users",
    headers={"Authorization": "Bearer ${TOKEN}"},
)
data = response.json()
for user in data["users"]:
    print(f"{user['name']} ({user['email']})")
```

## JavaScript (fetch)

```javascript
const response = await fetch("https://api.example.com/users", {
  headers: {
    "Authorization": `Bearer ${process.env.API_TOKEN}`,
    "Content-Type": "application/json",
  },
});
const data = await response.json();
console.log(data.users);
```

## Shell (curl)

```bash
# List all users
curl -s \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Accept: application/json" \
  https://api.example.com/users | jq .

# Create a user
curl -s -X POST \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice", "email": "alice@example.com"}' \
  https://api.example.com/users

# Delete a user
curl -s -X DELETE \
  -H "Authorization: Bearer $API_TOKEN" \
  https://api.example.com/users/123
```

## Go

```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "os"
)

func main() {
    req, _ := http.NewRequest("GET", "https://api.example.com/users", nil)
    req.Header.Set("Authorization", "Bearer "+os.Getenv("API_TOKEN"))

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()

    var data map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&data)
    fmt.Println(data)
}
```

## Ruby

```ruby
require "net/http"
require "json"

uri = URI("https://api.example.com/users")
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true

request = Net::HTTP::Get.new(uri)
request["Authorization"] = "Bearer #{ENV['API_TOKEN']}"
request["Accept"] = "application/json"

response = http.request(request)
data = JSON.parse(response.body)
puts data["users"]
```

## Error Handling

All examples should include proper error handling in production:

- Check HTTP status codes (200, 201 for success)
- Handle network timeouts gracefully
- Implement exponential backoff for rate limiting (429)
- Log errors with request context for debugging
